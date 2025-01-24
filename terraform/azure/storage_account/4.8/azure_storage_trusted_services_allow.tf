provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West Europe"
}

# Storage account with correct network rules configuration
resource "azurerm_storage_account" "pass_storage" {
  provider                 = azurerm.pass_aws
  name                     = "passstorage"
  resource_group_name      = azurerm_resource_group.pass_rg.name
  location                 = azurerm_resource_group.pass_rg.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  network_rules {
    default_action = "Deny"                # Correct: Restricts default access
    bypass         = ["AzureServices"]     # Correct: Allows trusted Azure services
    ip_rules       = ["100.0.0.0/24"]     # Optional: Allowed IP ranges
    virtual_network_subnet_ids = []        # Optional: Allowed VNet subnets
  }

  tags = {
    environment = "production"
  }
}