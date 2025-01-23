provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

# Key Vault without private endpoint
resource "azurerm_key_vault" "fail_vault" {
  provider                    = azurerm.fail_aws
  name                        = "fail-keyvault"
  location                    = azurerm_resource_group.fail_rg.location
  resource_group_name         = azurerm_resource_group.fail_rg.name
  tenant_id                   = "00000000-0000-0000-0000-000000000000"
  sku_name                    = "standard"
  
  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}
