# AWS Provider configuration
provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Non-compliant Redshift cluster configuration
resource "aws_redshift_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "fail-redshift-cluster"
  database_name      = "faildb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  
  # Automatic upgrades disabled - non-compliant
  allow_version_upgrade = false

  tags = {
    Environment = "test"
  }
}