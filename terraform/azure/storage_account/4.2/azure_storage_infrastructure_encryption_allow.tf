provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_storage_account" "pass_storage" {
  provider                         = azurerm.pass_aws
  name                             = "passstorage"
  resource_group_name              = azurerm_resource_group.pass_rg.name
  location                         = azurerm_resource_group.pass_rg.location
  account_tier                     = "Standard"
  account_replication_type         = "GRS"
  infrastructure_encryption_enabled = true
  min_tls_version                  = "TLS1_2"
  
  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action = "Deny"
    ip_rules       = ["10.0.0.0/24"]
  }

  tags = {
    environment = "production"
  }
}