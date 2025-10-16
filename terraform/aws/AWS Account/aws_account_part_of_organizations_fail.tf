# This example demonstrates an AWS account that is not part of an organization
resource "aws_account" "standalone_account" {
  account_id = "123456789012"
  name       = "Standalone Account"
  email      = "standalone@example.com"
  # Note: organization_id is not set, indicating this account is not part of an organization
}
