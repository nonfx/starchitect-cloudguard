# AWS Provider configuration
provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# OpenSearch domain configuration with all security features enabled
resource "aws_opensearch_domain" "pass_test" {
  provider    = aws.pass_aws
  domain_name = "pass-test-domain"

  # Cluster configuration
  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 2
  }

  # Node-to-node encryption enabled
  node_to_node_encryption {
    enabled = true
  }

  # At-rest encryption enabled
  encrypt_at_rest {
    enabled = true
  }

  # HTTPS enforcement and TLS configuration
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  # EBS storage configuration
  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  tags = {
    Environment = "production"
  }
}
