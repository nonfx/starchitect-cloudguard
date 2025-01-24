provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-rg"
  location = "West US"
}

resource "azurerm_monitor_action_group" "fail_action" {
  provider            = azurerm.fail_aws
  name                = "fail-action-group"
  resource_group_name = azurerm_resource_group.fail_rg.name
  short_name          = "fail-act"

  email_receiver {
    name          = "admin"
    email_address = "admin@example.com"
  }
}

resource "azurerm_monitor_activity_log_alert" "fail_alert" {
  provider            = azurerm.fail_aws
  name                = "fail-nsg-alert"
  resource_group_name = azurerm_resource_group.fail_rg.name
  scopes              = [azurerm_resource_group.fail_rg.id]
  enabled             = false

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Network/networkSecurityGroups/read"
  }

  action {
    action_group_id = azurerm_monitor_action_group.fail_action.id
  }
}