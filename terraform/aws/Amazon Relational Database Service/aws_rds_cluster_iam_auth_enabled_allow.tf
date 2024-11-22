provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# RDS Cluster configuration that passes the IAM authentication check
resource "aws_rds_cluster" "pass_cluster" {
  provider                          = aws.pass_aws
  cluster_identifier                = "pass-aurora-cluster"
  engine                            = "aurora-postgresql"
  engine_version                    = "13.6"
  database_name                     = "mydb"
  master_username                   = "admin"
  master_password                   = "somepassword123"
  backup_retention_period           = 7
  preferred_backup_window           = "07:00-09:00"
  # IAM authentication is explicitly enabled
  iam_database_authentication_enabled = true
  storage_encrypted                 = true

  # Additional security configurations
  serverlessv2_scaling_configuration {
    max_capacity = 1.0
    min_capacity = 0.5
  }

  tags = {
    Environment = "production"
    Compliance  = "enabled"
  }
}
