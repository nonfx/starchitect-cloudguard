provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Security Center setting with agentless scanning disabled
resource "azurerm_security_center_setting" "fail_setting" {
  provider = azurerm.fail_aws
  setting_name = "MCAS"
  enabled      = false
}

# Subscription with default security settings
resource "azurerm_subscription" "fail_subscription" {
  provider = azurerm.fail_aws
  subscription_name = "fail-subscription"
  subscription_id   = "00000000-0000-0000-0000-000000000000"
}
