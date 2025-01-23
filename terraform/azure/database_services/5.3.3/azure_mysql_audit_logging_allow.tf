provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_mysql_flexible_server" "pass_server" {
  provider = azurerm.pass_aws
  name                = "pass-mysql-server"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
  
  administrator_login    = "mysqladmin"
  administrator_password = "H@Sh1CoR3!"
  
  sku_name = "B_Standard_B1s"
  version  = "8.0.21"
}

# Compliant: Audit logging enabled
resource "azurerm_mysql_flexible_server_configuration" "pass_config" {
  provider = azurerm.pass_aws
  name                = "audit_log_enabled"
  resource_group_name = azurerm_resource_group.pass_rg.name
  server_name         = azurerm_mysql_flexible_server.pass_server.name
  value               = "ON"
}