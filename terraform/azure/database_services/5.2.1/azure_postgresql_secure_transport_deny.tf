provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

resource "azurerm_postgresql_flexible_server" "fail_server" {
  provider            = azurerm.fail_aws
  name                = "fail-psql-server"
  resource_group_name = azurerm_resource_group.fail_rg.name
  location            = azurerm_resource_group.fail_rg.location
  version             = "13"

  administrator_login    = "psqladmin"
  administrator_password = "H@Sh1CoR3!"

  storage_mb = 32768
  sku_name   = "B_Standard_B1ms"
}

# Non-compliant: require_secure_transport set to OFF
resource "azurerm_postgresql_flexible_server_configuration" "fail_config" {
  provider  = azurerm.fail_aws
  server_id = azurerm_postgresql_flexible_server.fail_server.id
  name      = "require_secure_transport"
  value     = "OFF"
}