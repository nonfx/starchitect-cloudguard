provider "azurerm" {
  alias = "fail_azure"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# Create resource group
resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_azure
  name     = "fail-rg"
  location = "West US"
}

# Create Key Vault
resource "azurerm_key_vault" "fail_vault" {
  provider                    = azurerm.fail_azure
  name                        = "fail-keyvault"
  location                    = azurerm_resource_group.fail_rg.location
  resource_group_name         = azurerm_resource_group.fail_rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  sku_name                    = "standard"
}

# Create Key Vault Key without expiration date
resource "azurerm_key_vault_key" "fail_key" {
  provider     = azurerm.fail_azure
  name         = "fail-key"
  key_vault_id = azurerm_key_vault.fail_vault.id
  key_type     = "RSA"
  key_size     = 2048
  
  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}