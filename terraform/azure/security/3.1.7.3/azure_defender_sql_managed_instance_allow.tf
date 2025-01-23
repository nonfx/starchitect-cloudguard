provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Configure Security Center subscription pricing with SQL protection
resource "azurerm_security_center_subscription_pricing" "pass_test" {
  provider      = azurerm.pass_aws
  tier          = "Standard"
  resource_type = "SqlServers"
}

# Resource group for SQL server
resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# SQL server with advanced security features
resource "azurerm_mssql_server" "pass_sql" {
  provider            = azurerm.pass_aws
  name                = "pass-sqlserver"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
  version             = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd123!"

  azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = "00000000-0000-0000-0000-000000000000"
  }

  identity {
    type = "SystemAssigned"
  }

  public_network_access_enabled = false

  tags = {
    Environment = "Production"
  }
}