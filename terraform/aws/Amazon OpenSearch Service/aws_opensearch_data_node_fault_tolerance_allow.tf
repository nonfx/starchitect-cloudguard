provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_opensearch_domain" "pass_domain" {
  provider = aws.pass_aws
  domain_name = "pass-test-domain"

  cluster_config {
    instance_type = "t3.small.search"
    instance_count = 3  # Compliant: 3 or more nodes
    zone_awareness_enabled = true  # Compliant: Zone awareness enabled

    zone_awareness_config {
      availability_zone_count = 3
    }
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  tags = {
    Environment = "production"
  }
}