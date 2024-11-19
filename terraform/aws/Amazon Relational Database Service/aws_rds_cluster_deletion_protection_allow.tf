provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_rds_cluster" "pass_test" {
  provider = aws.pass_aws
  cluster_identifier = "pass-test-cluster"
  engine = "aurora-mysql"
  engine_version = "5.7.mysql_aurora.2.10.2"
  database_name = "testdb"
  master_username = "admin"
  master_password = "password123"
  
  # Enable deletion protection
  deletion_protection = true
  
  # Enable backup retention
  backup_retention_period = 7
  preferred_backup_window = "03:00-04:00"
  
  # Enable encryption
  storage_encrypted = true
  
  tags = {
    Environment = "production"
    ManagedBy = "terraform"
  }
}