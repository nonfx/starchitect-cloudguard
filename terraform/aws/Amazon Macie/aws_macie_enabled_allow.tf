# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create Macie configuration with enabled status and publishing frequency
resource "aws_macie2_account" "pass" {
  status = "ENABLED"  # Enable Macie for the account
  finding_publishing_frequency = "FIFTEEN_MINUTES"  # Set the frequency for publishing findings
}
