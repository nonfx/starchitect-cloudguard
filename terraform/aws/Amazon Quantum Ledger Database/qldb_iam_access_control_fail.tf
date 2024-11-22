# Provider configuration
provider "aws" {
  region = var.region
}

# Create a QLDB ledger without IAM authentication
resource "aws_qldb_ledger" "example" {
  name             = "example-ledger"
  permissions_mode = "ALLOW_ALL"
}

# Variables
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}
