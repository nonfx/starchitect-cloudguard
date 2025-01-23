provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Security center contact with alerts to admins disabled
resource "azurerm_security_center_contact" "fail_contact" {
  name = "security-contact"
  provider = azurerm.fail_aws
  email = "admin@example.com"
  phone = "+1-555-555-5555"
  
  alert_notifications = true
  alerts_to_admins = false  # This makes it non-compliant
}
