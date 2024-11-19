provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_opensearch_domain" "fail_domain" {
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

  tags = {
    Environment = "test"
  }
}