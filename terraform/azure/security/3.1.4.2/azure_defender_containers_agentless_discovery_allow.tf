provider "azurerm" {
  features {}
}

resource "azurerm_security_center_subscription_pricing" "pass_test" {
  tier          = "Standard"
  resource_type = "ContainerRegistry"

  extension {
    name = "AgentlessDiscoveryForKubernetes"
  }
}

resource "azurerm_resource_group" "pass_rg" {
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_container_registry" "pass_acr" {
  name                = "passcontainerregistry"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
  sku                 = "Premium"
  admin_enabled       = false

  identity {
    type = "SystemAssigned"
  }

}