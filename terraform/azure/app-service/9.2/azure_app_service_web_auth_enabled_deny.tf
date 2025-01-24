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

resource "azurerm_windows_web_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    application_stack {
      dotnet_version = "v6.0"
      current_stack  = "dotnet"
    }
  }

  auth_settings_v2 {

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