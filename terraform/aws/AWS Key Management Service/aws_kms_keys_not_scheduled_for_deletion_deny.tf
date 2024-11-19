# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create a KMS key that fails the policy (scheduled for deletion)
resource "aws_kms_key" "fail_key" {
  description = "Example KMS key scheduled for deletion"
  deletion_window_in_days = 7  # Setting deletion window makes the key scheduled for deletion

  tags = {
    Environment = "Test"
    Purpose     = "Policy-Test-Fail"
  }
}
