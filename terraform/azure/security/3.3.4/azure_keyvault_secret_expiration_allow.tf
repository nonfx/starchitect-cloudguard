provider "azurerm" {
  alias = "pass_aws"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# Create resource group
resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-rg"
  location = "West US"
}

# Create Key Vault with RBAC disabled
resource "azurerm_key_vault" "pass_vault" {
  provider                    = azurerm.pass_aws
  name                        = "pass-vault"
  location                    = azurerm_resource_group.pass_rg.location
  resource_group_name         = azurerm_resource_group.pass_rg.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  enable_rbac_authorization   = false
  
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete"
    ]
  }
}

# Create secret with expiration date
resource "azurerm_key_vault_secret" "pass_secret" {
  provider        = azurerm.pass_aws
  name            = "pass-secret"
  value           = "mysecretvalue"
  key_vault_id    = azurerm_key_vault.pass_vault.id
  expiration_date = timeadd(timestamp(), "8760h")  # 1 year expiration
}
