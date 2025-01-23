provider "azurerm" {
  alias = "fail_azure"
  features {}
}

# Security center contact with notifications disabled
resource "azurerm_security_center_contact" "fail_contact" {
  provider = azurerm.fail_azure
  name = "security_contact"
  email = "security@example.com"
  phone = "+1-555-555-5555"
  
  alert_notifications = false  # Disabled notifications make it non-compliant
  alerts_to_admins = false    # Disabled admin alerts make it non-compliant
}
