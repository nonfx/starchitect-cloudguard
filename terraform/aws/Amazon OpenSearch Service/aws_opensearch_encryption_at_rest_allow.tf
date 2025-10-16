# Configure AWS provider for the passing test case
provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create KMS key for encryption
resource "aws_kms_key" "pass_key" {
  provider = aws.pass_aws
  description = "KMS key for OpenSearch encryption"
  deletion_window_in_days = 7
}

# Create an OpenSearch domain with encryption at rest enabled
resource "aws_opensearch_domain" "pass_domain" {
  provider = aws.pass_aws
  domain_name = "pass-domain"

  # Configure basic cluster settings
  cluster_config {
    instance_type = "t3.small.search"
    instance_count = 1
  }

  # Configure EBS storage
  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # Enable encryption at rest using KMS key
  encrypt_at_rest {
    enabled = true
    kms_key_id = aws_kms_key.pass_key.key_id
  }

  # Add tags for resource identification
  tags = {
    Environment = "production"
  }
}
