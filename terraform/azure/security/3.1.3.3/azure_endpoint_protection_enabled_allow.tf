provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Security Center setting with endpoint protection enabled
resource "azurerm_security_center_setting" "pass_endpoint_protection" {
  provider = azurerm.pass_aws
  setting_name = "WDATP"
  enabled      = true
}

# Security Center subscription pricing with standard tier
resource "azurerm_security_center_subscription_pricing" "pass_pricing" {
  provider = azurerm.pass_aws
  tier     = "Standard"
  resource_type = "VirtualMachines"
}

# Enable auto provisioning of monitoring agent
resource "azurerm_security_center_auto_provisioning" "pass_auto_provisioning" {
  provider = azurerm.pass_aws
  auto_provision = "On"
}