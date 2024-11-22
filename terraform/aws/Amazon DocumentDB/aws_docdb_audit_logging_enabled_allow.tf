provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_docdb_cluster" "pass_test" {
  provider              = aws.pass_aws
  cluster_identifier    = "pass-docdb-cluster"
  engine                = "docdb"
  master_username       = "admin"
  master_password       = "password123"
  storage_encrypted     = true
  skip_final_snapshot   = false
  deletion_protection   = true
  backup_retention_period = 7

  # Enable audit logging to CloudWatch Logs
  enabled_cloudwatch_logs_exports = ["audit", "profiler"]

  tags = {
    Environment = "test"
  }
}
