provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Configure Security Center subscription pricing without Key Vault protection
resource "azurerm_security_center_subscription_pricing" "fail_test" {
  provider      = azurerm.fail_aws
  tier          = "Free"
  resource_type = "KeyVaults"
}

# Resource group for key vault
resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

# Key vault without Defender protection
resource "azurerm_key_vault" "fail_kv" {
  provider                    = azurerm.fail_aws
  name                        = "failkeyvault"
  location                    = azurerm_resource_group.fail_rg.location
  resource_group_name         = azurerm_resource_group.fail_rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  sku_name                    = "standard"
}