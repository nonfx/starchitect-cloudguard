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

resource "azurerm_linux_web_app" "example" {
  name                = "linux-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    application_stack {
      node_version = "16-lts"
    }
  }

  auth_settings_v2 {
    auth_enabled           = true
    require_authentication = true

    login {
      token_store_enabled = true
    }

    active_directory_v2 {
      client_id                  = "your-client-id"
      client_secret_setting_name = "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET"
      tenant_auth_endpoint       = "https://login.microsoftonline.com/your-tenant-id/v2.0"
    }
  }

  app_settings = {
    "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET" = "your-client-secret"
  }
}