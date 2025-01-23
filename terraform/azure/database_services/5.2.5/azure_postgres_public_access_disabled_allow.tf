provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_virtual_network" "pass_vnet" {
  provider = azurerm.pass_aws
  name                = "pass-vnet"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "pass_subnet" {
  provider = azurerm.pass_aws
  name                 = "pass-subnet"
  resource_group_name  = azurerm_resource_group.pass_rg.name
  virtual_network_name = azurerm_virtual_network.pass_vnet.name
  address_prefixes     = ["10.0.2.0/24"]
  service_endpoints    = ["Microsoft.Storage"]
  delegation {
    name = "fs"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

resource "azurerm_postgresql_flexible_server" "pass_server" {
  provider = azurerm.pass_aws
  name                = "pass-psqlflexibleserver"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
  version             = "12"
  delegated_subnet_id = azurerm_subnet.pass_subnet.id
  private_dns_zone_id = azurerm_private_dns_zone.pass_dns.id
  administrator_login = "psqladmin"
  administrator_password = "H@Sh1CoR3!"
  storage_mb          = 32768
  sku_name            = "GP_Standard_D2s_v3"

  depends_on = [azurerm_private_dns_zone_virtual_network_link.pass_dns_link]
}

# Compliant: Only allow specific IP range
resource "azurerm_postgresql_flexible_server_firewall_rule" "pass_rule" {
  provider = azurerm.pass_aws
  name                = "AllowSpecificRange"
  server_id           = azurerm_postgresql_flexible_server.pass_server.id
  start_ip_address    = "192.168.1.0"
  end_ip_address      = "192.168.1.255"
}