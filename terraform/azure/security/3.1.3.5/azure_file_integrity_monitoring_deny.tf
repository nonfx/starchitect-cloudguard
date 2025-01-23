provider "azurerm" {
  features {}
}

# Enable Defender for Servers Plan 2 (required for FIM)
resource "azurerm_security_center_subscription_pricing" "server_plan2" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
  subplan       = "P2"
}

# Enable FIM component
resource "azurerm_security_center_setting" "fim" {
  setting_name = "FileIntegrity"
  enabled      = false

  depends_on = [azurerm_security_center_subscription_pricing.server_plan2]
}