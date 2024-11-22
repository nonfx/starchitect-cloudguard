provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_redshift_cluster" "pass_test" {
  provider = aws.pass_aws
  cluster_identifier = "pass-redshift-cluster"
  database_name      = "passdb"
  master_username    = "customadmin"  # Using custom admin username which will pass the test
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  tags = {
    Environment = "production"
    Name        = "pass-redshift-cluster"
  }
}
