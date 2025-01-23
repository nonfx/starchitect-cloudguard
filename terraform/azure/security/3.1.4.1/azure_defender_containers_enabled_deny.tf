provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Configure Microsoft Defender for Containers with Free tier (non-compliant)
resource "azurerm_security_center_subscription_pricing" "fail_containers" {
  provider        = azurerm.fail_aws
  tier            = "Free"
  resource_type   = "Containers"
}

# Configure subscription with disabled container security
resource "azurerm_security_center_setting" "fail_mcas" {
  provider      = azurerm.fail_aws
  setting_name  = "MCAS"
  enabled       = false
}
