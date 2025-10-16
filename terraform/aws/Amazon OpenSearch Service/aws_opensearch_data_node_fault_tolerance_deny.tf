provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_opensearch_domain" "fail_domain" {
  provider = aws.fail_aws
  domain_name = "fail-test-domain"

  cluster_config {
    instance_type = "t3.small.search"
    instance_count = 2  # Non-compliant: Less than 3 nodes
    zone_awareness_enabled = false  # Non-compliant: Zone awareness disabled
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  tags = {
    Environment = "test"
  }
}