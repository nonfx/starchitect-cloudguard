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
  provider = azurerm.fail_aws
  name                = "fail-psqlflexibleserver"
  resource_group_name = azurerm_resource_group.fail_rg.name
  location            = azurerm_resource_group.fail_rg.location
  version             = "12"
  administrator_login  = "psqladmin"
  administrator_password = "H@Sh1CoR3!"
  storage_mb          = 32768
  sku_name            = "GP_Standard_D2s_v3"
}

# Non-compliant: Allow all Azure services
resource "azurerm_postgresql_flexible_server_firewall_rule" "fail_rule" {
  provider = azurerm.fail_aws
  name                = "AllowAllAzureServices"
  server_id           = azurerm_postgresql_flexible_server.fail_server.id
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "0.0.0.0"
}