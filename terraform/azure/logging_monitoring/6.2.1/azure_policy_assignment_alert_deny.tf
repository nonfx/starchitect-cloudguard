provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-rg"
  location = "West US"
}

# Create action group for alerts
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

# Create incorrectly configured activity log alert
resource "azurerm_monitor_activity_log_alert" "fail_alert" {
  provider            = azurerm.fail_aws
  name                = "fail-policy-alert"
  resource_group_name = azurerm_resource_group.fail_rg.name
  scopes              = [azurerm_resource_group.fail_rg.id]
  enabled             = true

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/roleAssignments/write"  # Wrong operation
  }

  action {
    action_group_id = azurerm_monitor_action_group.fail_action.id
  }
}
