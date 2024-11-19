provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# This Elasticsearch domain will pass the policy check as it uses the latest TLS security policy
resource "aws_elasticsearch_domain" "pass_test" {
  provider = aws.pass_aws
  domain_name = "pass-test-domain"
  elasticsearch_version = "7.10"

  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-2-PFS-2023-10"  # Using latest TLS policy
  }

  cluster_config {
    instance_type = "t3.small.elasticsearch"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # Additional security best practices
  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }
}
