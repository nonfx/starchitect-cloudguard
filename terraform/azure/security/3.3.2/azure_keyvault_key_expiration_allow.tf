provider "azurerm" {
  alias = "pass_azure"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# Create resource group
resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_azure
  name     = "pass-rg"
  location = "West US"
}

# Create Key Vault
resource "azurerm_key_vault" "pass_vault" {
  provider                    = azurerm.pass_azure
  name                        = "pass-keyvault"
  location                    = azurerm_resource_group.pass_rg.location
  resource_group_name         = azurerm_resource_group.pass_rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true
  sku_name                    = "standard"
}

# Create Key Vault Key with expiration date
resource "azurerm_key_vault_key" "pass_key" {
  provider        = azurerm.pass_azure
  name            = "pass-key"
  key_vault_id    = azurerm_key_vault.pass_vault.id
  key_type        = "RSA"
  key_size        = 2048
  expiration_date = timeadd(timestamp(), "8760h")  # 1 year from creation
  
  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}