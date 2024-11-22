# Configure AWS provider for the passing test case
provider "aws" {
  region = "us-west-2"
}

# Create a KMS key for encryption
resource "aws_kms_key" "pass_test" {
  description = "KMS key for DocumentDB cluster encryption"
  enable_key_rotation = true  # Enable key rotation for better security
}

# Create an encrypted DocumentDB cluster (compliant)
resource "aws_docdb_cluster" "pass_test" {
  cluster_identifier = "pass-docdb-cluster"
  engine             = "docdb"
  master_username    = "foo"
  master_password    = "mustbeeightchars"
  storage_encrypted  = true  # Enable encryption
  kms_key_id        = aws_kms_key.pass_test.arn  # Use the created KMS key
  
  # Additional security configurations
  backup_retention_period = 7
  skip_final_snapshot    = false
  final_snapshot_identifier = "final-snapshot"
}
