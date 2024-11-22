# Configure AWS provider for the failing test case
provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create a Kinesis stream without encryption
resource "aws_kinesis_stream" "fail_stream" {
  provider = aws.fail_aws
  name = "fail-stream"
  shard_count = 1
  retention_period = 24

  # Deliberately omitting encryption configuration to demonstrate non-compliance
}
