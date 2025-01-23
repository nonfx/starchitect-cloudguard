provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Create auto provisioning setting with auto_provision set to On
resource "azurerm_security_center_auto_provisioning" "pass_test" {
  provider = azurerm.pass_aws
  auto_provision = "On"
}

# Create Log Analytics workspace
resource "azurerm_log_analytics_workspace" "pass_workspace" {
  provider = azurerm.pass_aws
  name                = "pass-log-analytics-workspace"
  location            = "westus2"
  resource_group_name = "pass-resource-group"
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Environment = "Production"
  }
}
