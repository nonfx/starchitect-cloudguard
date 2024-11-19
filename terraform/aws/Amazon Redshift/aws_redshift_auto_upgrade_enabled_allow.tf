# AWS Provider configuration
provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Compliant Redshift cluster configuration
resource "aws_redshift_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "pass-redshift-cluster"
  database_name      = "passdb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  
  # Automatic upgrades enabled - compliant
  allow_version_upgrade = true

  tags = {
    Environment = "production"
  }
}