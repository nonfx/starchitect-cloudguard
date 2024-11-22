provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_redshift_cluster" "fail_test" {
  provider = aws.fail_aws
  cluster_identifier = "fail-redshift-cluster"
  database_name      = "faildb"
  master_username    = "awsuser"  # Using default admin username which will fail the test
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  tags = {
    Environment = "test"
    Name        = "fail-redshift-cluster"
  }
}
