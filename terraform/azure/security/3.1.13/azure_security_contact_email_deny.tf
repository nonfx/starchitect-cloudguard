provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Security center contact with missing/invalid configuration
resource "azurerm_security_center_contact" "fail_contact" {
  provider = azurerm.fail_aws
  name = "security_contact"
  email = ""  # Empty email makes it non-compliant
  phone = "+1-555-555-5555"
  
  alert_notifications = true
  alerts_to_admins = true
}
