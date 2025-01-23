provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_postgresql_flexible_server" "pass_server" {
  provider = azurerm.pass_aws
  name                = "pass-psql-fs"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
  version             = "13"
  
  administrator_login    = "psqladmin"
  administrator_password = "H@Sh1CoR3!"

  storage_mb = 32768
  sku_name   = "B_Standard_B1ms"

  # Enable backup retention
  backup_retention_days = 7

  # Enable high availability
  high_availability {
    mode = "ZoneRedundant"
  }
}

# Compliant configuration with connection throttling enabled
resource "azurerm_postgresql_flexible_server_configuration" "pass_config" {
  provider = azurerm.pass_aws
  name                = "connection_throttle.enable"
  server_id           = azurerm_postgresql_flexible_server.pass_server.id
  value               = "on"
}