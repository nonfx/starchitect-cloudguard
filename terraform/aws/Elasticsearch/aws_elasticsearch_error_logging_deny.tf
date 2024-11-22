provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create Elasticsearch domain without error logging
resource "aws_elasticsearch_domain" "fail_example" {
  provider = aws.fail_aws
  domain_name = "fail-es-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
    instance_count = 2
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  tags = {
    Environment = "development"
  }
}