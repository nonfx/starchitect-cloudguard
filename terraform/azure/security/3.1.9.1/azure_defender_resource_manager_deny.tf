provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Configure Security Center subscription pricing without Resource Manager protection
resource "azurerm_security_center_subscription_pricing" "fail_test" {
  provider      = azurerm.fail_aws
  tier          = "Free"
  resource_type = "Arm"
}

# Resource group without proper protection
resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
  
  tags = {
    environment = "test"
  }
}