provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Configure Microsoft Defender for Containers with Standard tier (compliant)
resource "azurerm_security_center_subscription_pricing" "pass_containers" {
  provider        = azurerm.pass_aws
  tier            = "Standard"
  resource_type   = "Containers"
}

# Enable additional security settings
resource "azurerm_security_center_setting" "pass_mcas" {
  provider      = azurerm.pass_aws
  setting_name  = "MCAS"
  enabled       = true
}

# Configure auto provisioning of monitoring agent
resource "azurerm_security_center_auto_provisioning" "pass_auto" {
  provider        = azurerm.pass_aws
  auto_provision  = "On"
}
