provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# Virtual Network for private endpoint
resource "azurerm_virtual_network" "pass_vnet" {
  provider            = azurerm.pass_aws
  name                = "pass-vnet"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
  address_space       = ["10.0.0.0/16"]
}

# Subnet for private endpoint
resource "azurerm_subnet" "pass_subnet" {
  provider             = azurerm.pass_aws
  name                 = "pass-subnet"
  resource_group_name  = azurerm_resource_group.pass_rg.name
  virtual_network_name = azurerm_virtual_network.pass_vnet.name
  address_prefixes     = ["10.0.1.0/24"]

}

# Key Vault with private endpoint
resource "azurerm_key_vault" "pass_vault" {
  provider            = azurerm.pass_aws
  name                = "pass-keyvault"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"

  network_acls {
    default_action = "Deny"
    bypass         = "None"
  }
}

# Private endpoint for Key Vault
resource "azurerm_private_endpoint" "pass_endpoint" {
  provider            = azurerm.pass_aws
  name                = "pass-endpoint"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  subnet_id           = azurerm_subnet.pass_subnet.id

  private_service_connection {
    name                           = "pass-connection"
    private_connection_resource_id = azurerm_key_vault.pass_vault.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }
}
