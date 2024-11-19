# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create EMR block public access configuration that will fail the test
# This configuration allows multiple ports and has block_public_security_group_rules disabled
resource "aws_emr_block_public_access_configuration" "fail" {
  block_public_security_group_rules = false

  permitted_public_security_group_rule_range {
    min_range = 100
    max_range = 80
  }
}
