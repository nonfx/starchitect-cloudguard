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
  deletion_protection   = false
  storage_encrypted     = true
  skip_final_snapshot   = false
  backup_retention_period = 7

  tags = {
    Environment = "test"
  }
}
