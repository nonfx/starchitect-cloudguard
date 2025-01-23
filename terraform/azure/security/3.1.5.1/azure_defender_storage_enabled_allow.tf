provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Configure Security Center subscription pricing with Storage protection
resource "azurerm_security_center_subscription_pricing" "pass_test" {
  provider      = azurerm.pass_aws
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

# Resource group for storage account
resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# Storage account with security features
resource "azurerm_storage_account" "pass_storage" {
  provider                 = azurerm.pass_aws
  name                     = "passstorage"
  resource_group_name      = azurerm_resource_group.pass_rg.name
  location                 = azurerm_resource_group.pass_rg.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  min_tls_version = "TLS1_2"

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
  }
}