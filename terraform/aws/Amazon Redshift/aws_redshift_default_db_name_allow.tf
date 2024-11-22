provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_redshift_cluster" "pass_test" {
  provider = aws.pass_aws
  cluster_identifier = "pass-redshift-cluster"
  database_name      = "customdb"  # Using custom database name which will pass the test
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  tags = {
    Environment = "production"
    Name        = "pass-redshift-cluster"
  }
}
