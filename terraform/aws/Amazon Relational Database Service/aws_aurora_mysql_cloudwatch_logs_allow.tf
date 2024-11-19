# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create an Aurora MySQL cluster with audit logs enabled
resource "aws_rds_cluster" "pass_cluster" {
  cluster_identifier     = "aurora-cluster-pass"
  engine                 = "aurora-mysql"
  engine_version         = "5.7.mysql_aurora.2.11.2"
  database_name          = "mydb"
  master_username        = "admin"
  master_password        = "changeme123"
  skip_final_snapshot    = true

  # CloudWatch logs exports including audit logs
  enabled_cloudwatch_logs_exports = [
    "audit",
    "error",
    "slowquery"
  ]

  tags = {
    Environment = "production"
  }
}
