provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_sql_server" "pass_server" {
  provider = azurerm.pass_aws
  name                         = "pass-sqlserver"
  resource_group_name          = azurerm_resource_group.pass_rg.name
  location                     = azurerm_resource_group.pass_rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!"
}

# Compliant firewall rule with specific IP range
resource "azurerm_sql_firewall_rule" "pass_rule" {
  provider = azurerm.pass_aws
  name                = "office-network"
  resource_group_name = azurerm_resource_group.pass_rg.name
  server_name         = azurerm_sql_server.pass_server.name
  start_ip_address    = "192.168.1.0"
  end_ip_address      = "192.168.1.255"
}