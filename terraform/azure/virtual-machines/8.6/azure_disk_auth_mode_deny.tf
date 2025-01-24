provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-disk-rg"
  location = "eastus"
}

resource "azurerm_managed_disk" "fail" {
  provider = azurerm.fail_aws
  name                 = "fail-disk"
  location             = azurerm_resource_group.fail_rg.location
  resource_group_name  = azurerm_resource_group.fail_rg.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 1
  
  network_access_policy = "AllowAll"
  public_network_access_enabled = true

  tags = {
    environment = "test"
  }
}