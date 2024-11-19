# Configure AWS provider for the failing test case
provider "aws" {
  region = "us-west-2"
}

# Create a Kinesis stream with insufficient retention period
resource "aws_kinesis_stream" "fail_stream" {
  name             = "fail-stream"
  shard_count      = 1
  retention_period = 24  # Fails compliance - only 24 hours retention

  # Basic stream configuration
  encryption_type = "KMS"
  kms_key_id     = "alias/aws/kinesis"

  tags = {
    Environment = "test"
    Purpose     = "compliance-testing"
  }
}
