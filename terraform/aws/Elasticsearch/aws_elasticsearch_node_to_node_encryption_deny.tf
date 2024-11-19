provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_elasticsearch_domain" "fail_domain" {
  provider    = aws.fail_aws
  domain_name = "fail-es-domain"

  elasticsearch_version = "7.10"

  cluster_config {
    instance_type  = "t3.small.elasticsearch"
    instance_count = 2
  }

  # Node-to-node encryption disabled
  node_to_node_encryption {
    enabled = false
  }

  tags = {
    Environment = "test"
  }
}
