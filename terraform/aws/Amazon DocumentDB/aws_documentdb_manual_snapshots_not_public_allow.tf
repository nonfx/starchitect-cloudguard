provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create DocumentDB cluster
resource "aws_docdb_cluster" "pass_cluster" {
  provider                  = aws.pass_aws
  cluster_identifier        = "pass-docdb-cluster"
  engine                    = "docdb"
  master_username           = "admin"
  master_password           = "password123"
  backup_retention_period   = 5
  preferred_backup_window   = "07:00-09:00"
  skip_final_snapshot      = true

  tags = {
    Environment = "production"
  }
}

# Create private cluster snapshot
resource "aws_db_cluster_snapshot" "pass_snapshot" {
  provider                  = aws.pass_aws
  db_cluster_identifier     = aws_docdb_cluster.pass_cluster.id
  db_cluster_snapshot_identifier = "pass-snapshot"
  # No shared_accounts specified - snapshot remains private

  tags = {
    Environment = "production"
    Confidentiality = "private"
  }
}
