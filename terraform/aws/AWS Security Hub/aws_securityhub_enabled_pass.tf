provider "aws" {
  region = "us-west-2"
}

resource "aws_securityhub_account" "example" {
  auto_enable_controls = false
}

output "securityhub_account_id" {
  value = aws_securityhub_account.example.id
}
