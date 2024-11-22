# Provider configuration
provider "aws" {
  region = var.region
}

# Create a DocumentDB cluster without IAM authentication
resource "aws_docdb_cluster" "example" {
  cluster_identifier      = "example-cluster"
  engine                  = "docdb"
  master_username         = "exampleuser"
  master_password         = "examplepassword"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true
}

# Variables
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}
