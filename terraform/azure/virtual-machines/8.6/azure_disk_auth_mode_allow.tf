provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-disk-rg"
  location = "eastus"
}

resource "azurerm_disk_access" "pass" {
  provider = azurerm.pass_aws
  name                = "pass-disk-access"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
}

resource "azurerm_managed_disk" "pass" {
  provider = azurerm.pass_aws
  name                 = "pass-disk"
  location             = azurerm_resource_group.pass_rg.location
  resource_group_name  = azurerm_resource_group.pass_rg.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 1
  
  network_access_policy = "AllowPrivate"
  public_network_access_enabled = false
  disk_access_id = azurerm_disk_access.pass.id

  tags = {
    environment = "production"
  }
}