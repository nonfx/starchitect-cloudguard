provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_mssql_server" "pass_server" {
  provider = azurerm.pass_aws
  name                         = "pass-sqlserver"
  resource_group_name          = azurerm_resource_group.pass_rg.name
  location                     = azurerm_resource_group.pass_rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!"
}

# Compliant: Database with encryption enabled
resource "azurerm_mssql_database" "pass_db" {
  provider = azurerm.pass_aws
  name           = "pass-database"
  server_id      = azurerm_mssql_server.pass_server.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  license_type   = "LicenseIncluded"
  max_size_gb    = 2
  sku_name       = "Basic"
  
  transparent_data_encryption_enabled = true

  threat_detection_policy {
    state = "Enabled"
    email_account_admins = true
    retention_days = 30
  }

  tags = {
    Environment = "Production"
    Security    = "High"
  }
}