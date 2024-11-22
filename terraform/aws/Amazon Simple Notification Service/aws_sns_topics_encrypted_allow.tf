provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create KMS key for SNS encryption
resource "aws_kms_key" "pass_sns" {
  provider = aws.pass_aws
  description = "KMS key for SNS topic encryption"
  enable_key_rotation = true

  tags = {
    Environment = "production"
  }
}

# Create SNS topic with KMS encryption
resource "aws_sns_topic" "pass_test" {
  provider = aws.pass_aws
  name = "pass-test-topic"
  kms_master_key_id = aws_kms_key.pass_sns.id

  tags = {
    Environment = "production"
    Purpose = "secure-messaging"
  }
}
