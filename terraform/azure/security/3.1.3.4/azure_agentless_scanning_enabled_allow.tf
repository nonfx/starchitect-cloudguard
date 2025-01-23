provider "azurerm" {
  alias           = "pass_aws"
  subscription_id = "11111111-1111-1111-1111-111111111111"
  features {}
}

# Security Center setting with agentless scanning enabled
resource "azurerm_security_center_setting" "pass_setting" {
  provider     = azurerm.pass_aws
  setting_name = "MCAS"
  enabled      = true
}

# Subscription with security settings properly configured
resource "azurerm_subscription" "pass_subscription" {
  provider          = azurerm.pass_aws
  subscription_name = "pass-subscription"
  subscription_id   = "11111111-1111-1111-1111-111111111111"
}

# Security Center workspace
resource "azurerm_log_analytics_workspace" "pass_workspace" {
  provider            = azurerm.pass_aws
  name                = "pass-security-workspace"
  location            = "eastus"
  resource_group_name = "pass-security-group"
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# Security Center workspace binding
resource "azurerm_security_center_workspace" "pass_workspace_binding" {
  provider     = azurerm.pass_aws
  scope        = "/subscriptions/11111111-1111-1111-1111-111111111111"
  workspace_id = azurerm_log_analytics_workspace.pass_workspace.id
}