provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West Europe"
}

# Storage account with cross-tenant replication enabled
resource "azurerm_storage_account" "fail_storage" {
  provider                        = azurerm.fail_aws
  name                            = "failstorage"
  resource_group_name             = azurerm_resource_group.fail_rg.name
  location                        = azurerm_resource_group.fail_rg.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  allow_cross_tenant_replication  = true  # Non-compliant: Cross-tenant replication enabled

  tags = {
    environment = "test"
  }
}