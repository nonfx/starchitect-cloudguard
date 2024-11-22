provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_redshift_cluster" "fail_test" {
  provider = aws.fail_aws
  cluster_identifier = "fail-redshift-cluster"
  database_name      = "faildb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  
  # Automated snapshot retention period set to less than 7 days
  automated_snapshot_retention_period = 3
  
  skip_final_snapshot = true
  
  tags = {
    Environment = "test"
    Name        = "fail-redshift-cluster"
  }
}