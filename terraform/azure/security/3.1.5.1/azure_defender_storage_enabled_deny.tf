provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Configure Security Center subscription pricing without Storage protection
resource "azurerm_security_center_subscription_pricing" "fail_test" {
  provider      = azurerm.fail_aws
  tier          = "Free"
  resource_type = "StorageAccounts"
}

# Resource group for storage account
resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

# Storage account without security features
resource "azurerm_storage_account" "fail_storage" {
  provider                 = azurerm.fail_aws
  name                     = "failstorage"
  resource_group_name      = azurerm_resource_group.fail_rg.name
  location                 = azurerm_resource_group.fail_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}