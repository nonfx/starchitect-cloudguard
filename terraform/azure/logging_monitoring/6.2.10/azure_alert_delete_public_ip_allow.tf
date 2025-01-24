provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-rg"
  location = "West US"
}

resource "azurerm_monitor_action_group" "pass_action" {
  provider            = azurerm.pass_aws
  name                = "pass-action-group"
  resource_group_name = azurerm_resource_group.pass_rg.name
  short_name          = "pass-act"

  email_receiver {
    name          = "admin"
    email_address = "admin@example.com"
  }
}

# Create properly configured activity log alert
resource "azurerm_monitor_activity_log_alert" "pass_alert" {
  provider            = azurerm.pass_aws
  name                = "pass-ip-alert"
  resource_group_name = azurerm_resource_group.pass_rg.name
  scopes              = [azurerm_resource_group.pass_rg.id]
  enabled             = true

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Network/publicIPAddresses/delete"
  }

  action {
    action_group_id = azurerm_monitor_action_group.pass_action.id
  }

  tags = {
    Environment = "Production"
    Purpose     = "IP Monitoring"
  }
}