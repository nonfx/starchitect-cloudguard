provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Security Center subscription pricing with Standard tier (compliant)
resource "azurerm_security_center_subscription_pricing" "pass_servers" {
  provider      = azurerm.pass_aws
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

# Additional security center contact configuration
resource "azurerm_security_center_contact" "pass_contact" {
  provider = azurerm.pass_aws
  name     = "azurerm_security_center_contact"
  email    = "security@example.com"
  phone    = "+1-555-555-5555"

  alert_notifications = true
  alerts_to_admins    = true
}