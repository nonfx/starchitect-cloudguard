# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create EMR block public access configuration that will pass the test
# This configuration only allows port 22 and has block_public_security_group_rules enabled
resource "aws_emr_block_public_access_configuration" "pass" {
  block_public_security_group_rules = true

  # Only allow SSH access on port 22
  permitted_public_security_group_rule_range {
    min_range = 22
    max_range = 22
  }
}
