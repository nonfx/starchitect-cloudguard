provider "aws" {
  region = "us-west-2"
}

resource "aws_rds_cluster" "fail_test" {
  cluster_identifier     = "fail-test-cluster"
  engine                 = "aurora-postgresql"
  engine_version         = "13.6"
  database_name          = "testdb"
  master_username        = "testuser"
  master_password        = "password123!"
  skip_final_snapshot    = true

  # CloudWatch Logs exports not configured - will fail the test

  tags = {
    Environment = "test"
    Name        = "fail-test-cluster"
  }
}
