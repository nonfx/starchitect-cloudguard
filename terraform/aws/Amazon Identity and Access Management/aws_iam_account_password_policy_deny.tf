# Define the AWS provider
provider "aws" {
  region = "us-east-1"  # Adjust the region as necessary
}

# Define IAM password policy
resource "aws_iam_account_password_policy" "exampledeny" {
  minimum_password_length    = 5
  require_uppercase_characters = true
  require_lowercase_characters = true
  require_numbers              = true
  require_symbols              = true
  allow_users_to_change_password = true
  hard_expiry                  = false
  max_password_age             = 60
  password_reuse_prevention    = 5
}

resource "aws_iam_account_password_policy" "exampleempty" {
  # minimum_password_length    = 5
  require_uppercase_characters = true
  require_lowercase_characters = true
  require_numbers              = true
  require_symbols              = true
  allow_users_to_change_password = true
  hard_expiry                  = false
  max_password_age             = 60
  password_reuse_prevention    = 5
}
