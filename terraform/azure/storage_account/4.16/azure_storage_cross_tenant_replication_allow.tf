provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West Europe"
}

# Storage account with cross-tenant replication disabled
resource "azurerm_storage_account" "pass_storage" {
  provider                        = azurerm.pass_aws
  name                            = "passstorage"
  resource_group_name             = azurerm_resource_group.pass_rg.name
  location                        = azurerm_resource_group.pass_rg.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  allow_cross_tenant_replication  = false  # Compliant: Cross-tenant replication disabled

  tags = {
    environment = "production"
  }
}