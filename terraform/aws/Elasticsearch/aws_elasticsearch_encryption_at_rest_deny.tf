provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create Elasticsearch domain without encryption at rest
resource "aws_elasticsearch_domain" "fail_domain" {
  provider = aws.fail_aws
  domain_name = "fail-es-domain"
  
  cluster_config {
    instance_type = "r6g.large.elasticsearch"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  tags = {
    Environment = "development"
  }
}