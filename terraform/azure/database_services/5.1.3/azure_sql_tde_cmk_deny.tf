provider "azurerm" {
  alias = "fail_aws"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
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

# Non-compliant: Using service-managed key for TDE
resource "azurerm_mssql_server_transparent_data_encryption" "fail_tde" {
  provider = azurerm.fail_aws
  server_id = azurerm_mssql_server.fail_server.id
}