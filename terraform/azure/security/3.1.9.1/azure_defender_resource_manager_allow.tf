provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Configure Security Center subscription pricing with Resource Manager protection
resource "azurerm_security_center_subscription_pricing" "pass_test" {
  provider      = azurerm.pass_aws
  tier          = "Standard"
  resource_type = "Arm"
}

# Resource group with proper protection
resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
  
  tags = {
    environment = "production"
    security_tier = "high"
  }
}

# Lock the resource group to prevent accidental deletion
resource "azurerm_management_lock" "pass_lock" {
  provider   = azurerm.pass_aws
  name       = "resource-group-lock"
  scope      = azurerm_resource_group.pass_rg.id
  lock_level = "CanNotDelete"
  notes      = "Protected resource group that cannot be deleted"
}