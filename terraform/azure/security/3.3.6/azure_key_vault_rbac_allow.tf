provider "azurerm" {
  alias = "pass_aws"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# Key Vault with RBAC enabled
resource "azurerm_key_vault" "pass_vault" {
  provider                    = azurerm.pass_aws
  name                        = "pass-keyvault"
  location                    = azurerm_resource_group.pass_rg.location
  resource_group_name         = azurerm_resource_group.pass_rg.name
  tenant_id                   = "00000000-0000-0000-0000-000000000000"
  sku_name                    = "standard"
  enable_rbac_authorization   = true
}

# RBAC role assignment for the Key Vault
resource "azurerm_role_assignment" "pass_role" {
  provider             = azurerm.pass_aws
  scope                = azurerm_key_vault.pass_vault.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = "11111111-1111-1111-1111-111111111111"
}
