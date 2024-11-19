provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_rds_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "pass-aurora-cluster"
  engine = "aurora-mysql"
  engine_version = "5.7.mysql_aurora.2.10.2"
  database_name = "mydb"
  master_username = "admin"
  master_password = "password123"
  copy_tags_to_snapshot = true
  backup_retention_period = 7
  preferred_backup_window = "03:00-04:00"

  tags = {
    Environment = "production"
    Project = "example"
    Backup = "enabled"
  }
}