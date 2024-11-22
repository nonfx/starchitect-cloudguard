provider "aws" {
  region = "us-west-2"
}

resource "aws_rds_cluster" "pass_test" {
  cluster_identifier     = "pass-test-cluster"
  engine                 = "aurora-postgresql"
  engine_version         = "13.6"
  database_name          = "testdb"
  master_username        = "testuser"
  master_password        = "password123!"
  skip_final_snapshot    = true

  # Enable PostgreSQL logs export to CloudWatch Logs - will pass the test
  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = {
    Environment = "production"
    Name        = "pass-test-cluster"
  }
}
