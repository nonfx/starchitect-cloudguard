provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West Europe"
}

resource "azurerm_app_service_plan" "pass_plan" {
  provider            = azurerm.pass_aws
  name                = "pass-appserviceplan"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name

  sku {
    tier = "Standard"
    size = "S1"
  }
}

resource "azurerm_app_service" "pass_app" {
  provider            = azurerm.pass_aws
  name                = "pass-app-service"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  app_service_plan_id = azurerm_app_service_plan.pass_plan.id

  site_config {
    min_tls_version = "1.2"
    http2_enabled = true
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Production"
  }
}