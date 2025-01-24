provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-rg"
  location = "eastus"
}

# Create Key Vault
resource "azurerm_key_vault" "pass_kv" {
  provider                    = azurerm.pass_aws
  name                        = "pass-keyvault"
  location                    = azurerm_resource_group.pass_rg.location
  resource_group_name         = azurerm_resource_group.pass_rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true
  sku_name                    = "standard"
}

# Create Key Vault Key
resource "azurerm_key_vault_key" "pass_key" {
  provider     = azurerm.pass_aws
  name         = "disk-encryption-key"
  key_vault_id = azurerm_key_vault.pass_kv.id
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

# Create Disk Encryption Set
resource "azurerm_disk_encryption_set" "pass_des" {
  provider            = azurerm.pass_aws
  name                = "pass-des"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
  key_vault_key_id    = azurerm_key_vault_key.pass_key.id

  identity {
    type = "SystemAssigned"
  }
}

# Create managed disk with CMK encryption
resource "azurerm_managed_disk" "pass_disk" {
  provider                = azurerm.pass_aws
  name                    = "pass-disk"
  location                = azurerm_resource_group.pass_rg.location
  resource_group_name     = azurerm_resource_group.pass_rg.name
  storage_account_type    = "Standard_LRS"
  create_option           = "Empty"
  disk_size_gb            = 1
  disk_encryption_set_id = azurerm_disk_encryption_set.pass_des.id

  encryption_settings {
    enabled = true
  }

  tags = {
    environment = "production"
  }
}