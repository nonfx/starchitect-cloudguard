provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_rds_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "fail-aurora-cluster"
  engine = "aurora-mysql"
  engine_version = "5.7.mysql_aurora.2.10.2"
  database_name = "mydb"
  master_username = "admin"
  master_password = "password123"
  copy_tags_to_snapshot = false

  tags = {
    Environment = "test"
    Project = "example"
  }
}