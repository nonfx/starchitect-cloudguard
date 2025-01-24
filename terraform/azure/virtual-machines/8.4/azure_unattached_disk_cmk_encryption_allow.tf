provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-disk-rg"
  location = "eastus"
}

# Create Key Vault
resource "azurerm_key_vault" "pass" {
  provider = azurerm.pass_aws
  name                = "pass-keyvault"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium"

  soft_delete_retention_days = 7
  purge_protection_enabled   = true
}

# Create encryption key
resource "azurerm_key_vault_key" "pass" {
  provider = azurerm.pass_aws
  name         = "pass-encryption-key"
  key_vault_id = azurerm_key_vault.pass.id
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

# Create disk encryption set
resource "azurerm_disk_encryption_set" "pass" {
  provider = azurerm.pass_aws
  name                = "pass-disk-encryption-set"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
  key_vault_key_id    = azurerm_key_vault_key.pass.id

  identity {
    type = "SystemAssigned"
  }
}

# Create unattached disk with CMK encryption
resource "azurerm_managed_disk" "pass" {
  provider = azurerm.pass_aws
  name                 = "pass-disk"
  location             = azurerm_resource_group.pass_rg.location
  resource_group_name  = azurerm_resource_group.pass_rg.name
  storage_account_type = "Premium_LRS"
  create_option        = "Empty"
  disk_size_gb         = 32

  disk_encryption_set_id = azurerm_disk_encryption_set.pass.id
  encryption_settings {
    enabled = true
  }

  tags = {
    environment = "production"
  }
}