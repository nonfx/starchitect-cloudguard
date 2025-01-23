provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Security Center subscription pricing with Free tier (non-compliant)
resource "azurerm_security_center_subscription_pricing" "fail_servers" {
  provider = azurerm.fail_aws
  tier          = "Free"
  resource_type = "VirtualMachines"
}