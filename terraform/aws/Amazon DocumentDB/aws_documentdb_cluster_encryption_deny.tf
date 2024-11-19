# Configure AWS provider for the failing test case
provider "aws" {
  region = "us-west-2"
}

# Create an unencrypted DocumentDB cluster (non-compliant)
resource "aws_docdb_cluster" "fail_test" {
  cluster_identifier = "fail-docdb-cluster"
  engine             = "docdb"
  master_username    = "foo"
  master_password    = "mustbeeightchars"
  storage_encrypted  = false  # Explicitly disable encryption
}
