provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create Redshift cluster with enhanced VPC routing enabled
resource "aws_redshift_cluster" "pass_test" {
  provider = aws.pass_aws
  cluster_identifier = "pass-redshift-cluster"
  database_name      = "passdb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  
  enhanced_vpc_routing = true

  tags = {
    Environment = "production"
  }
}
