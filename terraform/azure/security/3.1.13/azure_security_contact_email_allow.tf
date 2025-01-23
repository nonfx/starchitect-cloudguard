provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Security center contact with proper configuration
resource "azurerm_security_center_contact" "pass_contact" {
  provider = azurerm.pass_aws
  name = "security_contact"
  email = "security@example.com"  # Valid email address
  phone = "+1-555-555-5555"
  
  alert_notifications = true
  alerts_to_admins = true
}
