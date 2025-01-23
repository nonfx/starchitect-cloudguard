provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Configure Security Center subscription pricing without SQL Servers protection
resource "azurerm_security_center_subscription_pricing" "fail_test" {
  provider      = azurerm.fail_aws
  tier          = "Free"
  resource_type = "SqlServerVirtualMachines"
}

# Resource group for SQL Server
resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

# SQL Server without proper protection
resource "azurerm_mssql_server" "fail_sql" {
  provider            = azurerm.fail_aws
  name                = "fail-sqlserver"
  resource_group_name = azurerm_resource_group.fail_rg.name
  location            = azurerm_resource_group.fail_rg.location
  version             = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!"

  public_network_access_enabled = true
}