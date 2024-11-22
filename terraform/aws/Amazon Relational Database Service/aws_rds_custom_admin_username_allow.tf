provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_rds_cluster" "pass_test" {
  provider = aws.pass_aws
  cluster_identifier = "pass-test-cluster"
  engine = "aurora-mysql"
  engine_version = "5.7.mysql_aurora.2.10.2"
  database_name = "mydb"
  master_username = "customadmin"  # Using custom admin username
  master_password = "test1234!"
  skip_final_snapshot = true

  backup_retention_period = 7
  preferred_backup_window = "03:00-04:00"

  tags = {
    Environment = "production"
    Name = "pass-test-cluster"
  }
}
