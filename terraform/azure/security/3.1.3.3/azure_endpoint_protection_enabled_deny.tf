provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Security Center setting with endpoint protection disabled
resource "azurerm_security_center_setting" "fail_endpoint_protection" {
  provider = azurerm.fail_aws
  setting_name = "WDATP"
  enabled      = false
}

# Security Center subscription pricing with standard tier
resource "azurerm_security_center_subscription_pricing" "fail_pricing" {
  provider = azurerm.fail_aws
  tier     = "Standard"
  resource_type = "VirtualMachines"
}