provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-disk-rg"
  location = "eastus"
}

# Create unattached disk without CMK encryption
resource "azurerm_managed_disk" "fail" {
  provider = azurerm.fail_aws
  name                 = "fail-disk"
  location             = azurerm_resource_group.fail_rg.location
  resource_group_name  = azurerm_resource_group.fail_rg.name
  storage_account_type = "Premium_LRS"
  create_option        = "Empty"
  disk_size_gb         = 32

  # No disk encryption set configured
  encryption_settings {
    enabled = false
  }

  tags = {
    environment = "test"
  }
}