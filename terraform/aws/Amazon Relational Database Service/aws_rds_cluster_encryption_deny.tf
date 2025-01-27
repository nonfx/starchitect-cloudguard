provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_rds_cluster" "fail_test" {
  provider               = aws.fail_aws
  cluster_identifier     = "fail-test-cluster"
  engine                 = "aurora-mysql"
  engine_version         = "5.7.mysql_aurora.2.10.2"
  database_name          = "testdb"
  master_username        = "admin"
  master_password        = "password123!"
  storage_encrypted      = false  # Encryption disabled
  skip_final_snapshot    = true

  tags = {
    Environment = "test"
    Name        = "fail-test-cluster"
  }
}
