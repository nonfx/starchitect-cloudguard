provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# OpenSearch domain with insecure TLS configuration
resource "aws_opensearch_domain" "fail_domain" {
  provider = aws.fail_aws
  
  domain_name    = "fail-example-domain"
  engine_version = "OpenSearch_1.0"

  cluster_config {
    instance_type = "t3.small.search"
  }

  # Insecure configuration with older TLS policy and HTTPS not enforced
  domain_endpoint_options {
    enforce_https = false
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}