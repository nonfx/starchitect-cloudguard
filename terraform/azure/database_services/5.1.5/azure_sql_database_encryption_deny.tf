provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
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

# Non-compliant: Database without encryption enabled
resource "azurerm_mssql_database" "fail_db" {
  provider = azurerm.fail_aws
  name           = "fail-database"
  server_id      = azurerm_mssql_server.fail_server.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  license_type   = "LicenseIncluded"
  max_size_gb    = 2
  sku_name       = "Basic"
  
  transparent_data_encryption_enabled = false
}