provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

resource "azurerm_sql_server" "fail_server" {
  provider = azurerm.fail_aws
  name                         = "fail-sqlserver"
  resource_group_name          = azurerm_resource_group.fail_rg.name
  location                     = azurerm_resource_group.fail_rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!"
}

# Non-compliant firewall rule allowing all IPs
resource "azurerm_sql_firewall_rule" "fail_rule" {
  provider = azurerm.fail_aws
  name                = "allow-all-azure"
  resource_group_name = azurerm_resource_group.fail_rg.name
  server_name         = azurerm_sql_server.fail_server.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}