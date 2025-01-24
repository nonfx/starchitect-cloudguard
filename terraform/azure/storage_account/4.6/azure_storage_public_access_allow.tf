provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West Europe"
}

# Storage account with public network access disabled (compliant)
resource "azurerm_storage_account" "pass_storage" {
  provider                    = azurerm.pass_aws
  name                        = "passstorage"
  resource_group_name         = azurerm_resource_group.pass_rg.name
  location                    = azurerm_resource_group.pass_rg.location
  account_tier                = "Standard"
  account_replication_type    = "GRS"
  public_network_access_enabled = false

  network_rules {
    default_action = "Deny"
    ip_rules       = ["100.0.0.1"]
    virtual_network_subnet_ids = []
  }

  tags = {
    environment = "production"
  }
}
