provider "aws" {
  region = "us-west-2"
}

resource "aws_securityhub_account" "example" {}

output "securityhub_account_id" {
  value = aws_securityhub_account.example.id
}
