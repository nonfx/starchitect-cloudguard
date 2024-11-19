# Configure AWS provider for the passing test case
provider "aws" {
  region = "us-west-2"
}

# Create a Kinesis stream with compliant retention period
resource "aws_kinesis_stream" "pass_stream" {
  name             = "pass-stream"
  shard_count      = 1
  retention_period = 168  # Compliant - 7 days retention

  # Enhanced stream configuration
  encryption_type = "KMS"
  kms_key_id     = "alias/aws/kinesis"

  # Stream scaling configuration
  stream_mode_details {
    stream_mode = "ON_DEMAND"
  }

  tags = {
    Environment = "production"
    Purpose     = "compliance-testing"
    Compliance  = "true"
  }
}
