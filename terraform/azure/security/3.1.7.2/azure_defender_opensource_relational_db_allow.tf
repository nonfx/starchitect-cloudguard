provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Configure Security Center subscription pricing with Defender for Open-source relational databases
resource "azurerm_security_center_subscription_pricing" "pass_test" {
  provider      = azurerm.pass_aws
  tier          = "Standard"
  resource_type = "OpenSourceRelationalDatabases"
}

# Resource group for database
resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# PostgreSQL server with security features
resource "azurerm_postgresql_server" "pass_db" {
  provider            = azurerm.pass_aws
  name                = "pass-postgresql-server"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name

  sku_name = "GP_Gen5_2"

  storage_mb                   = 5120
  backup_retention_days        = 30
  geo_redundant_backup_enabled = true
  auto_grow_enabled           = true

  administrator_login          = "psqladmin"
  administrator_login_password = "H@Sh1CoR3!"
  version                     = "11"
  ssl_enforcement_enabled     = true

  threat_detection_policy {
    enabled              = true
    email_account_admins = true
    retention_days       = 30
  }

  identity {
    type = "SystemAssigned"
  }
}