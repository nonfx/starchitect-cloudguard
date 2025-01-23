provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

resource "azurerm_mysql_flexible_server" "fail_server" {
  provider = azurerm.fail_aws
  name                = "fail-mysql-server"
  resource_group_name = azurerm_resource_group.fail_rg.name
  location            = azurerm_resource_group.fail_rg.location
  administrator_login = "mysqladmin"
  administrator_password = "P@ssw0rd1234!"
  sku_name            = "B_Standard_B1s"
  version             = "8.0.21"
}

# Non-compliant: Using TLS version 1.1
resource "azurerm_mysql_flexible_server_configuration" "fail_tls" {
  provider = azurerm.fail_aws
  name                = "tls_version"
  resource_group_name = azurerm_resource_group.fail_rg.name
  server_name         = azurerm_mysql_flexible_server.fail_server.name
  value               = "TLSv1.1"
}