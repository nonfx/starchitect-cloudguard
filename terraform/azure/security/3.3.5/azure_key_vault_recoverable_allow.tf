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

# Key Vault with required protection features
resource "azurerm_key_vault" "pass_vault" {
  provider                    = azurerm.pass_aws
  name                        = "pass-keyvault"
  location                    = azurerm_resource_group.pass_rg.location
  resource_group_name         = azurerm_resource_group.pass_rg.name
  tenant_id                   = "00000000-0000-0000-0000-000000000000"
  soft_delete_retention_days  = 90
  purge_protection_enabled    = true
  sku_name                    = "standard"

  access_policy {
    tenant_id = "00000000-0000-0000-0000-000000000000"
    object_id = "11111111-1111-1111-1111-111111111111"
    key_permissions = ["Get"]
  }
}
