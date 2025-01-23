provider "azurerm" {
  features {}
}

resource "azurerm_security_center_subscription_pricing" "fail_test" {
  tier          = "Standard"
  resource_type = "ContainerRegistry"
}

resource "azurerm_resource_group" "fail_rg" {
  name     = "fail-resources"
  location = "West US"
}

resource "azurerm_container_registry" "fail_acr" {
  name                = "failcontainerregistry"
  resource_group_name = azurerm_resource_group.fail_rg.name
  location            = azurerm_resource_group.fail_rg.location
  sku                 = "Basic"
  admin_enabled       = true
}