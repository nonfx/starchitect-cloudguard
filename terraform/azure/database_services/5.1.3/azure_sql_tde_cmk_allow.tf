provider "azurerm" {
  alias = "pass_aws"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# Create Key Vault
resource "azurerm_key_vault" "pass_kv" {
  provider = azurerm.pass_aws
  name                = "pass-keyvault"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium"

  soft_delete_retention_days = 7
  purge_protection_enabled   = true

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get",
      "Create",
      "Delete",
      "List",
      "Restore",
      "Recover",
      "UnwrapKey",
      "WrapKey",
      "Purge",
      "Encrypt",
      "Decrypt",
      "Sign",
      "Verify"
    ]
  }
}

# Create Key Vault Key
resource "azurerm_key_vault_key" "pass_key" {
  provider = azurerm.pass_aws
  name         = "pass-tde-key"
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

resource "azurerm_mssql_server" "pass_server" {
  provider = azurerm.pass_aws
  name                         = "pass-sqlserver"
  resource_group_name          = azurerm_resource_group.pass_rg.name
  location                     = azurerm_resource_group.pass_rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!"
  identity {
    type = "SystemAssigned"
  }
}

# Grant SQL Server access to Key Vault
resource "azurerm_key_vault_access_policy" "pass_policy" {
  provider = azurerm.pass_aws
  key_vault_id = azurerm_key_vault.pass_kv.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_mssql_server.pass_server.identity[0].principal_id

  key_permissions = [
    "Get",
    "WrapKey",
    "UnwrapKey"
  ]
}

# Compliant: Using customer-managed key for TDE
resource "azurerm_mssql_server_transparent_data_encryption" "pass_tde" {
  provider = azurerm.pass_aws
  server_id        = azurerm_mssql_server.pass_server.id
  key_vault_key_id = azurerm_key_vault_key.pass_key.id

  depends_on = [azurerm_key_vault_access_policy.pass_policy]
}