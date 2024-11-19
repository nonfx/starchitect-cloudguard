provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "neptune-cluster-fail"
  engine = "neptune"
  
  # IAM authentication is disabled by default
  iam_database_authentication_enabled = false
  
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot = true
  
  tags = {
    Environment = "test"
  }
}