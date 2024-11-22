provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "neptune-cluster-pass"
  engine = "neptune"
  
  # Enable IAM authentication
  iam_database_authentication_enabled = true
  
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot = true
  
  tags = {
    Environment = "test"
  }
}