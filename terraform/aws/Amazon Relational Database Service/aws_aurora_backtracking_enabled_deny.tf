provider "aws" {
  region = "us-west-2"
}

# Aurora cluster without backtracking enabled - failing configuration
resource "aws_rds_cluster" "fail_cluster" {
  cluster_identifier = "aurora-cluster-fail"
  engine = "aurora-mysql"
  engine_version = "5.7.mysql_aurora.2.10.2"
  database_name = "mydb"
  master_username = "admin"
  master_password = "changeme123"
  skip_final_snapshot = true
  
  # No backtrack_window specified - failing condition
  
  tags = {
    Environment = "test"
  }
}