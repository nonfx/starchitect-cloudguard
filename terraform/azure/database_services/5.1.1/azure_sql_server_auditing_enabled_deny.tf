provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

resource "azurerm_storage_account" "fail_storage" {
  provider                 = azurerm.fail_aws
  name                     = "failsqlauditlogs"
  resource_group_name      = azurerm_resource_group.fail_rg.name
  location                 = azurerm_resource_group.fail_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_mssql_server" "fail_server" {
  provider                        = azurerm.fail_aws
  name                            = "fail-sqlserver"
  resource_group_name             = azurerm_resource_group.fail_rg.name
  location                        = azurerm_resource_group.fail_rg.location
  version                         = "12.0"
  administrator_login             = "sqladmin"
  administrator_login_password    = "P@ssw0rd123!"

  tags = {
    environment = "test"
  }
}

# Missing or disabled auditing policy makes this non-compliant