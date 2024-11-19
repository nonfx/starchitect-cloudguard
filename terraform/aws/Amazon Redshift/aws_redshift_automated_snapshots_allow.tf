provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_redshift_cluster" "pass_test" {
  provider = aws.pass_aws
  cluster_identifier = "pass-redshift-cluster"
  database_name      = "passdb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  
  # Automated snapshot retention period set to 7 days
  automated_snapshot_retention_period = 7
  
  skip_final_snapshot = true
  
  tags = {
    Environment = "production"
    Name        = "pass-redshift-cluster"
  }
}