provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Configure Security Center subscription pricing without Defender for Open-source relational databases
resource "azurerm_security_center_subscription_pricing" "fail_test" {
  provider      = azurerm.fail_aws
  tier          = "Free"
  resource_type = "OpenSourceRelationalDatabases"
}

# Resource group for database
resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

# PostgreSQL server without security features
resource "azurerm_postgresql_server" "fail_db" {
  provider            = azurerm.fail_aws
  name                = "fail-postgresql-server"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name

  sku_name = "B_Gen5_2"

  storage_mb                   = 5120
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  auto_grow_enabled           = true

  administrator_login          = "psqladmin"
  administrator_login_password = "H@Sh1CoR3!"
  version                     = "11"
  ssl_enforcement_enabled     = false
}