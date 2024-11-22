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
  deletion_protection   = true
  storage_encrypted     = true
  skip_final_snapshot   = false
  backup_retention_period = 7

  tags = {
    Environment = "test"
  }
}
