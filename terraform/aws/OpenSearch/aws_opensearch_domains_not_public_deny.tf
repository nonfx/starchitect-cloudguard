provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create OpenSearch domain without VPC configuration
resource "aws_opensearch_domain" "fail_test" {
  provider = aws.fail_aws
  domain_name = "fail-test-domain"
  
  cluster_config {
    instance_type = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled = true
  }

  tags = {
    Environment = "test"
  }
}