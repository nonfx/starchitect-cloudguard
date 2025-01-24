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

resource "azurerm_network_interface" "pass_nic" {
  provider = azurerm.pass_aws
  name                = "pass-nic"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.pass_subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "pass" {
  provider = azurerm.pass_aws
  name                = "pass-vm"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  size                = "Standard_F2"
  admin_username      = "adminuser"
  admin_password      = "P@ssw0rd1234!"
  network_interface_ids = [
    azurerm_network_interface.pass_nic.id,
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

  # Enable Trusted Launch features
  secure_boot_enabled = true
  vtpm_enabled        = true

  tags = {
    environment = "production"
  }
}