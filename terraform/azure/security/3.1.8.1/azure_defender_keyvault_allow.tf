provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Configure Security Center subscription pricing with Key Vault protection
resource "azurerm_security_center_subscription_pricing" "pass_test" {
  provider      = azurerm.pass_aws
  tier          = "Standard"
  resource_type = "KeyVaults"
}

# Resource group for key vault
resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# Key vault with Defender protection
resource "azurerm_key_vault" "pass_kv" {
  provider                    = azurerm.pass_aws
  name                        = "passkeyvault"
  location                    = azurerm_resource_group.pass_rg.location
  resource_group_name         = azurerm_resource_group.pass_rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true
  sku_name                    = "premium"

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}