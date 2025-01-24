provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-rg"
  location = "West US"
}

# Create action group for alerts
resource "azurerm_monitor_action_group" "pass_action" {
  provider            = azurerm.pass_aws
  name                = "pass-action-group"
  resource_group_name = azurerm_resource_group.pass_rg.name
  short_name          = "pass-act"

  email_receiver {
    name          = "admin"
    email_address = "admin@example.com"
  }

  sms_receiver {
    name         = "oncall"
    country_code = "1"
    phone_number = "5555555555"
  }
}

# Create properly configured activity log alert
resource "azurerm_monitor_activity_log_alert" "pass_alert" {
  provider            = azurerm.pass_aws
  name                = "pass-policy-alert"
  resource_group_name = azurerm_resource_group.pass_rg.name
  scopes              = [azurerm_resource_group.pass_rg.id]
  enabled             = true

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/policyAssignments/write"
    level          = "Warning"
  }

  action {
    action_group_id = azurerm_monitor_action_group.pass_action.id
  }

  tags = {
    Environment = "Production"
  }
}
