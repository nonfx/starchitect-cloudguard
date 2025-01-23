provider "azurerm" {
  alias = "fail_aws"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# Create resource group
resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-rg"
  location = "West US"
}

# Create Key Vault with RBAC disabled
resource "azurerm_key_vault" "fail_vault" {
  provider                    = azurerm.fail_aws
  name                        = "fail-vault"
  location                    = azurerm_resource_group.fail_rg.location
  resource_group_name         = azurerm_resource_group.fail_rg.name
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

# Create secret without expiration date
resource "azurerm_key_vault_secret" "fail_secret" {
  provider     = azurerm.fail_aws
  name         = "fail-secret"
  value        = "mysecretvalue"
  key_vault_id = azurerm_key_vault.fail_vault.id
  # No expiration_date set - non-compliant
}
