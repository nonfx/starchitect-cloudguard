provider "azurerm" {
  alias = "pass_aws"
  features {}
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# SQL Server with Microsoft Entra authentication configured
resource "azurerm_mssql_server" "pass_server" {
  provider = azurerm.pass_aws
  name                         = "pass-sqlserver"
  resource_group_name          = azurerm_resource_group.pass_rg.name
  location                     = azurerm_resource_group.pass_rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!"

  azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = data.azurerm_client_config.current.object_id
  }

  tags = {
    Environment = "production"
  }
}