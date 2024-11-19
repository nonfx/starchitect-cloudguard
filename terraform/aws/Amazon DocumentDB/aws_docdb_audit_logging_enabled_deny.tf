provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_docdb_cluster" "fail_test" {
  provider              = aws.fail_aws
  cluster_identifier    = "fail-docdb-cluster"
  engine                = "docdb"
  master_username       = "admin"
  master_password       = "password123"
  storage_encrypted     = true
  skip_final_snapshot   = false
  deletion_protection   = true
  backup_retention_period = 7

  # Audit logging is not enabled
  enabled_cloudwatch_logs_exports = ["profiler"]

  tags = {
    Environment = "test"
  }
}
