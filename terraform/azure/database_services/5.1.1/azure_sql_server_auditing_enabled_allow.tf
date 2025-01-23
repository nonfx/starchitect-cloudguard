provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_storage_account" "pass_storage" {
  provider                 = azurerm.pass_aws
  name                     = "passsqlauditlogs"
  resource_group_name      = azurerm_resource_group.pass_rg.name
  location                 = azurerm_resource_group.pass_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_mssql_server" "pass_server" {
  provider                        = azurerm.pass_aws
  name                            = "pass-sqlserver"
  resource_group_name             = azurerm_resource_group.pass_rg.name
  location                        = azurerm_resource_group.pass_rg.location
  version                         = "12.0"
  administrator_login             = "sqladmin"
  administrator_login_password    = "P@ssw0rd123!"

  tags = {
    environment = "production"
  }
}

resource "azurerm_mssql_server_extended_auditing_policy" "pass_policy" {
  provider            = azurerm.pass_aws
  server_id           = azurerm_mssql_server.pass_server.id
  storage_endpoint    = azurerm_storage_account.pass_storage.primary_blob_endpoint
  retention_in_days   = 90
  storage_account_access_key = azurerm_storage_account.pass_storage.primary_access_key
  enabled             = true
}