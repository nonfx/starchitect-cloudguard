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

resource "azurerm_network_interface" "fail_nic" {
  provider = azurerm.fail_aws
  name                = "fail-nic"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.fail_subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "fail" {
  provider = azurerm.fail_aws
  name                = "fail-vm"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
  size                = "Standard_F2"
  admin_username      = "adminuser"
  admin_password      = "P@ssw0rd1234!"
  network_interface_ids = [
    azurerm_network_interface.fail_nic.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2019-Datacenter"
    version   = "latest"
  }

  # Missing secure_boot_enabled and vtpm_enabled settings

  tags = {
    environment = "test"
  }
}