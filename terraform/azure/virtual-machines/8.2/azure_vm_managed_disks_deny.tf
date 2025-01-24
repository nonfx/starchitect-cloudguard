provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-vm-rg"
  location = "eastus"
}

resource "azurerm_virtual_network" "fail_vnet" {
  provider = azurerm.fail_aws
  name                = "fail-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
}

resource "azurerm_subnet" "fail_subnet" {
  provider = azurerm.fail_aws
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.fail_rg.name
  virtual_network_name = azurerm_virtual_network.fail_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_storage_account" "fail_sa" {
  provider = azurerm.fail_aws
  name                     = "failstorage"
  resource_group_name      = azurerm_resource_group.fail_rg.name
  location                 = azurerm_resource_group.fail_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_virtual_machine" "fail" {
  provider = azurerm.fail_aws
  name                  = "fail-vm"
  location              = azurerm_resource_group.fail_rg.location
  resource_group_name   = azurerm_resource_group.fail_rg.name
  network_interface_ids = [azurerm_network_interface.fail_nic.id]
  vm_size              = "Standard_DS1_v2"

  storage_os_disk {
    name          = "osdisk"
    vhd_uri       = "${azurerm_storage_account.fail_sa.primary_blob_endpoint}vhds/osdisk.vhd"
    caching       = "ReadWrite"
    create_option = "FromImage"
  }

  storage_data_disk {
    name          = "datadisk"
    vhd_uri       = "${azurerm_storage_account.fail_sa.primary_blob_endpoint}vhds/datadisk.vhd"
    disk_size_gb  = "100"
    create_option = "Empty"
    lun           = 0
  }

  os_profile {
    computer_name  = "hostname"
    admin_username = "testadmin"
    admin_password = "Password1234!"
  }

  os_profile_linux_config {
    disable_password_authentication = false
  }
}