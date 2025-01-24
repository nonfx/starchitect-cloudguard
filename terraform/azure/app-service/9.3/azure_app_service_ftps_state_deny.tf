provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West Europe"
}

resource "azurerm_app_service_plan" "fail_plan" {
  provider            = azurerm.fail_aws
  name                = "fail-appserviceplan"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name

  sku {
    tier = "Standard"
    size = "S1"
  }
}

resource "azurerm_app_service" "fail_app" {
  provider            = azurerm.fail_aws
  name                = "fail-app-service"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
  app_service_plan_id = azurerm_app_service_plan.fail_plan.id

  site_config {
    ftps_state = "AllAllowed"
    http2_enabled = true
  }

  tags = {
    Environment = "test"
  }
}