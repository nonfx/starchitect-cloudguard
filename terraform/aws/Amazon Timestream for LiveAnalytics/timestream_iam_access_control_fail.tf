# Provider configuration
provider "aws" {
  region = var.region
}

# Create a Timestream database without IAM authentication
resource "aws_timestreamwrite_database" "example" {
  database_name = "example-database"
}

# Variables
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}
