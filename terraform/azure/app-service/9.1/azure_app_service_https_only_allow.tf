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

  https_only = true

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                = "LocalGit"
    min_tls_version         = "1.2"
    ftps_state              = "FtpsOnly"
  }

  app_settings = {
    "WEBSITE_NODE_DEFAULT_VERSION" = "10.14.1"
  }

  identity {
    type = "SystemAssigned"
  }
}