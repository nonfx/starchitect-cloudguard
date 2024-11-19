# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create Macie configuration with disabled status
resource "aws_macie2_account" "fail" {
  status = "DISABLED"  # Explicitly disable Macie
}
