provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

# SQL Server without Microsoft Entra authentication configured
resource "azurerm_mssql_server" "fail_server" {
  provider = azurerm.fail_aws
  name                         = "fail-sqlserver"
  resource_group_name          = azurerm_resource_group.fail_rg.name
  location                     = azurerm_resource_group.fail_rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!"

  tags = {
    Environment = "test"
  }
}