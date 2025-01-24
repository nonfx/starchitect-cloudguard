provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Create a resource group
resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-diagnostics-rg"
  location = "West US"
}

# Create a Log Analytics workspace
resource "azurerm_log_analytics_workspace" "pass_law" {
  provider            = azurerm.pass_aws
  name                = "pass-law"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  sku                 = "PerGB2018"
}

# Create diagnostic setting with all required categories enabled
resource "azurerm_monitor_diagnostic_setting" "pass_setting" {
  provider               = azurerm.pass_aws
  name                   = "pass-diagnostic-setting"
  target_resource_id     = "/subscriptions/00000000-0000-0000-0000-000000000000"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.pass_law.id

  log {
    category = "Administrative"
    enabled  = true
  }

  log {
    category = "Alert"
    enabled  = true
  }

  log {
    category = "Policy"
    enabled  = true
  }

  log {
    category = "Security"
    enabled  = true
  }
}
