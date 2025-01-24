provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-vm-rg"
  location = "eastus"
}

resource "azurerm_virtual_network" "pass_vnet" {
  provider = azurerm.pass_aws
  name                = "pass-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
}

resource "azurerm_subnet" "pass_subnet" {
  provider = azurerm.pass_aws
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.pass_rg.name
  virtual_network_name = azurerm_virtual_network.pass_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_virtual_machine" "pass" {
  provider = azurerm.pass_aws
  name                  = "pass-vm"
  location              = azurerm_resource_group.pass_rg.location
  resource_group_name   = azurerm_resource_group.pass_rg.name
  network_interface_ids = [azurerm_network_interface.pass_nic.id]
  vm_size              = "Standard_DS1_v2"

  storage_os_disk {
    name              = "osdisk"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"
  }

  storage_data_disk {
    name              = "datadisk"
    managed_disk_type = "Standard_LRS"
    create_option     = "Empty"
    lun               = 0
    disk_size_gb      = 100
  }

  os_profile {
    computer_name  = "hostname"
    admin_username = "testadmin"
    admin_password = "Password1234!"
  }

  os_profile_linux_config {
    disable_password_authentication = false
  }

  tags = {
    Environment = "Production"
  }
}