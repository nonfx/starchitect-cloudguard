provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  name     = "pass-rg"
  location = "West US"
}

resource "azurerm_log_analytics_workspace" "pass_workspace" {
  name                = "pass-workspace"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_application_insights" "pass_insights" {
  name                = "pass-app-insights"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  workspace_id        = azurerm_log_analytics_workspace.pass_workspace.id
  application_type    = "web"
  retention_in_days   = 90

  tags = {
    Environment = "Production"
  }
}