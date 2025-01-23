provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Create auto provisioning setting with auto_provision set to Off
resource "azurerm_security_center_auto_provisioning" "fail_test" {
  provider = azurerm.fail_aws
  auto_provision = "Off"
}
