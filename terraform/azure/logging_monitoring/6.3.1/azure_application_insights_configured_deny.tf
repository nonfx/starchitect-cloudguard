provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  name     = "fail-rg"
  location = "West US"
}

resource "azurerm_application_insights" "fail_insights" {
  name                = "fail-app-insights"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
  application_type    = "invalid-type"
  retention_in_days   = 45

  tags = {
    Environment = "Test"
  }
}