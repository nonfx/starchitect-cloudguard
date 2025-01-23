provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_mysql_flexible_server" "pass_server" {
  provider            = azurerm.pass_aws
  name                = "pass-mysql-server"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location

  administrator_login    = "mysqladmin"
  administrator_password = "H@Sh1CoR3!"

  sku_name = "B_Standard_B1s"
  version  = "8.0.21"

  # Enable high availability
  high_availability {
    mode = "ZoneRedundant"
  }

  # Enable backup retention
  backup_retention_days = 7

  # Enable storage auto-growth
  storage {
    auto_grow_enabled = true
  }
}

# Compliant: audit_log_events includes CONNECTION
resource "azurerm_mysql_flexible_server_configuration" "pass_config" {
  provider            = azurerm.pass_aws
  name                = "audit_log_events"
  resource_group_name = azurerm_resource_group.pass_rg.name
  server_name         = azurerm_mysql_flexible_server.pass_server.name
  value               = "CONNECTION,QUERY,TABLE"
}

# Configure diagnostic settings for audit logs
resource "azurerm_monitor_diagnostic_setting" "pass_diag" {
  provider                   = azurerm.pass_aws
  name                       = "audit-logs"
  target_resource_id         = azurerm_mysql_flexible_server.pass_server.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.pass_law.id

  # log {
  #   category = "MySqlAuditLogs"
  #   enabled  = true

  #   retention_policy {
  #     enabled = true
  #     days    = 30
  #   }
  # }
}