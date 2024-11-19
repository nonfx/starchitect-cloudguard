provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create S3 bucket for Redshift logs
resource "aws_s3_bucket" "pass_redshift_logs" {
  provider = aws.pass_aws
  bucket = "pass-redshift-audit-logs-bucket"
}

# Create Redshift cluster
resource "aws_redshift_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "pass-redshift-cluster"
  database_name      = "passdb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  skip_final_snapshot = true

  tags = {
    Environment = "production"
  }
}

# Enable logging for the Redshift cluster
resource "aws_redshift_logging" "pass_logging" {
  provider = aws.pass_aws
  cluster_identifier = aws_redshift_cluster.pass_cluster.cluster_identifier
  bucket_name        = aws_s3_bucket.pass_redshift_logs.id
  s3_key_prefix      = "redshift-logs/"
}
