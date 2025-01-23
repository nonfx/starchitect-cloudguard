provider "azurerm" {
  alias = "fail_aws"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

# Key Vault without required protection features
resource "azurerm_key_vault" "fail_vault" {
  provider                    = azurerm.fail_aws
  name                        = "fail-keyvault"
  location                    = azurerm_resource_group.fail_rg.location
  resource_group_name         = azurerm_resource_group.fail_rg.name
  tenant_id                   = "00000000-0000-0000-0000-000000000000"
  soft_delete_retention_days  = 0
  purge_protection_enabled    = false
  sku_name                    = "standard"

  access_policy {
    tenant_id = "00000000-0000-0000-0000-000000000000"
    object_id = "11111111-1111-1111-1111-111111111111"
    key_permissions = ["Get"]
  }
}
