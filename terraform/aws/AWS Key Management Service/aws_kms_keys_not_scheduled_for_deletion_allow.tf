# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create a KMS key that passes the policy (not scheduled for deletion)
resource "aws_kms_key" "pass_key" {
  description = "Example KMS key not scheduled for deletion"
  # No deletion_window_in_days specified, so key is not scheduled for deletion

  tags = {
    Environment = "Production"
    Purpose     = "Policy-Test-Pass"
  }
}
