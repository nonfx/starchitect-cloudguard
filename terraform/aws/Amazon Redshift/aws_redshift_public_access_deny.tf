provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_redshift_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "fail-redshift-cluster"
  database_name      = "faildb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  
  publicly_accessible = true  # Non-compliant: Public access enabled

  tags = {
    Environment = "test"
  }
}