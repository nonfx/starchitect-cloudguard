provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# This Elasticsearch domain will fail the policy check because it uses an older TLS security policy
resource "aws_elasticsearch_domain" "fail_test" {
  provider = aws.fail_aws
  domain_name = "fail-test-domain"
  elasticsearch_version = "7.10"

  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"  # Using outdated TLS policy
  }

  cluster_config {
    instance_type = "t3.small.elasticsearch"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
