provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create DocumentDB cluster
resource "aws_docdb_cluster" "fail_cluster" {
  provider                  = aws.fail_aws
  cluster_identifier        = "fail-docdb-cluster"
  engine                    = "docdb"
  master_username           = "admin"
  master_password           = "password123"
  backup_retention_period   = 5
  preferred_backup_window   = "07:00-09:00"
  skip_final_snapshot      = true

  tags = {
    Environment = "test"
  }
}

# Create public cluster snapshot
resource "aws_db_cluster_snapshot" "fail_snapshot" {
  provider                  = aws.fail_aws
  db_cluster_identifier     = aws_docdb_cluster.fail_cluster.id
  db_cluster_snapshot_identifier = "fail-snapshot"
  shared_accounts           = ["all"]

  tags = {
    Environment = "test"
  }
}
