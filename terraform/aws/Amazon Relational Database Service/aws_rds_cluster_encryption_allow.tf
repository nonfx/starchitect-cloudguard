provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_rds_cluster" "pass_test" {
  provider               = aws.pass_aws
  cluster_identifier     = "pass-test-cluster"
  engine                 = "aurora-mysql"
  engine_version         = "5.7.mysql_aurora.2.10.2"
  database_name          = "testdb"
  master_username        = "admin"
  master_password        = "password123!"
  storage_encrypted      = true   # Encryption enabled
  skip_final_snapshot    = true

  tags = {
    Environment = "production"
    Name        = "pass-test-cluster"
  }
}
