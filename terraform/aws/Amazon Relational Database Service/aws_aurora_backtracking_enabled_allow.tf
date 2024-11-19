provider "aws" {
  region = "us-west-2"
}

# Aurora cluster with backtracking enabled - passing configuration
resource "aws_rds_cluster" "pass_cluster" {
  cluster_identifier = "aurora-cluster-pass"
  engine = "aurora-mysql"
  engine_version = "5.7.mysql_aurora.2.10.2"
  database_name = "mydb"
  master_username = "admin"
  master_password = "changeme123"
  skip_final_snapshot = true

  # Backtracking enabled with 24-hour window - passing condition
  backtrack_window = 86400  # 24 hours in seconds

  tags = {
    Environment = "production"
  }
}