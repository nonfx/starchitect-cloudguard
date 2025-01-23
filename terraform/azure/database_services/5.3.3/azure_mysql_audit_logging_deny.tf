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
  
  administrator_login    = "mysqladmin"
  administrator_password = "H@Sh1CoR3!"
  
  sku_name = "B_Standard_B1s"
  version  = "8.0.21"
}

# Non-compliant: Audit logging disabled
resource "azurerm_mysql_flexible_server_configuration" "fail_config" {
  provider = azurerm.fail_aws
  name                = "audit_log_enabled"
  resource_group_name = azurerm_resource_group.fail_rg.name
  server_name         = azurerm_mysql_flexible_server.fail_server.name
  value               = "OFF"
}