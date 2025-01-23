provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Security center contact with alerts to admins enabled
resource "azurerm_security_center_contact" "pass_contact" {
  name = "security-contact"
  provider = azurerm.pass_aws
  email = "admin@example.com"
  phone = "+1-555-555-5555"
  
  alert_notifications = true
  alerts_to_admins = true  # This makes it compliant
}
