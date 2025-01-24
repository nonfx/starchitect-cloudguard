provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-rg"
  location = "eastus"
}

# Create managed disk without CMK encryption
resource "azurerm_managed_disk" "fail_disk" {
  provider             = azurerm.fail_aws
  name                 = "fail-disk"
  location             = azurerm_resource_group.fail_rg.location
  resource_group_name  = azurerm_resource_group.fail_rg.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 1

  # No disk encryption set configured
  encryption_settings {
    enabled = false
  }

  tags = {
    environment = "test"
  }
}