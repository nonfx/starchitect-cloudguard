provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# RDS Cluster configuration that fails the IAM authentication check
resource "aws_rds_cluster" "fail_cluster" {
  provider                          = aws.fail_aws
  cluster_identifier                = "fail-aurora-cluster"
  engine                            = "aurora-postgresql"
  engine_version                    = "13.6"
  database_name                     = "mydb"
  master_username                   = "admin"
  master_password                   = "somepassword123"
  backup_retention_period           = 5
  preferred_backup_window           = "07:00-09:00"
  # IAM authentication is explicitly disabled
  iam_database_authentication_enabled = false

  tags = {
    Environment = "test"
  }
}
