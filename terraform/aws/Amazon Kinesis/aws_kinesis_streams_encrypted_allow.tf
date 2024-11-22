# Configure AWS provider for the passing test case
provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create a KMS key for encryption
resource "aws_kms_key" "pass_key" {
  provider = aws.pass_aws
  description = "KMS key for Kinesis stream encryption"
  deletion_window_in_days = 7
}

# Create a Kinesis stream with proper encryption
resource "aws_kinesis_stream" "pass_stream" {
  provider = aws.pass_aws
  name = "pass-stream"
  shard_count = 1
  retention_period = 24

  # Configure KMS encryption
  encryption_type = "KMS"
  kms_key_id = aws_kms_key.pass_key.id

  tags = {
    Environment = "Production"
    Purpose = "Data streaming"
  }
}
