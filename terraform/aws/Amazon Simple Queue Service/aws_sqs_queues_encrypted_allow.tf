provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create KMS key for SQS encryption
resource "aws_kms_key" "pass_sqs" {
  provider = aws.pass_aws
  description = "KMS key for SQS queue encryption"
  enable_key_rotation = true

  tags = {
    Environment = "production"
  }
}

# Create SQS queue with KMS encryption
resource "aws_sqs_queue" "pass_test" {
  provider = aws.pass_aws
  name = "pass-test-queue"
  kms_master_key_id = aws_kms_key.pass_sqs.id

  tags = {
    Environment = "production"
    Purpose = "secure-messaging"
  }
}
