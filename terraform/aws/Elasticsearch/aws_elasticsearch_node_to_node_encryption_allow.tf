provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_elasticsearch_domain" "pass_domain" {
  provider    = aws.pass_aws
  domain_name = "pass-es-domain"

  elasticsearch_version = "7.10"

  cluster_config {
    instance_type  = "t3.small.elasticsearch"
    instance_count = 2
  }

  # Node-to-node encryption enabled
  node_to_node_encryption {
    enabled = true
  }

  # Additional security configurations
  encrypt_at_rest {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  tags = {
    Environment = "production"
    Security    = "high"
  }
}
