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
  provider = azurerm.fail_aws
  name                     = "failstorage"
  resource_group_name      = azurerm_resource_group.fail_rg.name
  location                 = azurerm_resource_group.fail_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_mssql_server" "fail_server" {
  provider = azurerm.fail_aws
  name                         = "fail-sqlserver"
  resource_group_name          = azurerm_resource_group.fail_rg.name
  location                     = azurerm_resource_group.fail_rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!"
}

# Non-compliant: Retention period less than 90 days
resource "azurerm_mssql_server_extended_auditing_policy" "fail_policy" {
  provider = azurerm.fail_aws
  server_id        = azurerm_mssql_server.fail_server.id
  storage_endpoint = azurerm_storage_account.fail_storage.primary_blob_endpoint
  retention_in_days = 30
}