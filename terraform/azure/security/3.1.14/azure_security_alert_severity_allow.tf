provider "azurerm" {
  alias = "pass_azure"
  features {}
}

# Security center contact with notifications enabled
resource "azurerm_security_center_contact" "pass_contact" {
  provider = azurerm.pass_azure
  name = "security_contact"
  email = "security@example.com"
  phone = "+1-555-555-5555"
  
  alert_notifications = true  # Enabled notifications
  alerts_to_admins = true    # Enabled admin alerts
}
