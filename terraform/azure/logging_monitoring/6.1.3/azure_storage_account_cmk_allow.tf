provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West Europe"
}

# Create Key Vault
resource "azurerm_key_vault" "pass_kv" {
  provider            = azurerm.pass_aws
  name                = "pass-keyvault"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  purge_protection_enabled = true
}

# Create Key Vault Key
resource "azurerm_key_vault_key" "pass_key" {
  provider     = azurerm.pass_aws
  name         = "storage-key"
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

# Storage account with CMK encryption
resource "azurerm_storage_account" "pass_storage" {
  provider                 = azurerm.pass_aws
  name                     = "passstorage"
  resource_group_name      = azurerm_resource_group.pass_rg.name
  location                 = azurerm_resource_group.pass_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  identity {
    type = "SystemAssigned"
  }

  # Configure CMK encryption
  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.pass_key.id
    user_assigned_identity_id = azurerm_user_assigned_identity.pass_identity.id
  }

  tags = {
    environment = "production"
  }
}