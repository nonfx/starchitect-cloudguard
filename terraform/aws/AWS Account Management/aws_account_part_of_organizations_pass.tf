# This example demonstrates an AWS account that is part of an organization
resource "aws_account" "org_member_account" {
  account_id      = "987654321098"
  name            = "Organization Member Account"
  email           = "member@example.com"
  organization_id = "o-exampleorgid"
}
