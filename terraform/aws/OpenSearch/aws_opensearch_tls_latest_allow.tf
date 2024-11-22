provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# OpenSearch domain with secure TLS configuration
resource "aws_opensearch_domain" "pass_domain" {
  provider = aws.pass_aws
  
  domain_name    = "pass-example-domain"
  engine_version = "OpenSearch_1.0"

  cluster_config {
    instance_type = "t3.small.search"
  }

  # Secure configuration with latest TLS policy and HTTPS enforced
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  # Additional security best practices
  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }
}