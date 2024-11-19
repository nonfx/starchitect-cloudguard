provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create KMS key for Elasticsearch encryption
resource "aws_kms_key" "es_key" {
  provider = aws.pass_aws
  description = "KMS key for Elasticsearch encryption at rest"
  deletion_window_in_days = 7
}

# Create Elasticsearch domain with encryption at rest enabled
resource "aws_elasticsearch_domain" "pass_domain" {
  provider = aws.pass_aws
  domain_name = "pass-es-domain"

  cluster_config {
    instance_type = "r6g.large.elasticsearch"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled = true
    kms_key_id = aws_kms_key.es_key.key_id
  }

  tags = {
    Environment = "production"
    Security = "encrypted"
  }
}