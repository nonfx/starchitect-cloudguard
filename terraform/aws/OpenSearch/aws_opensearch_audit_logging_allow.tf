provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_cloudwatch_log_group" "pass_log_group" {
  provider = aws.pass_aws
  name     = "/aws/opensearch/domains/pass-domain/audit-logs"
}

resource "aws_opensearch_domain" "pass_domain" {
  provider = aws.pass_aws
  domain_name = "pass-test-domain"

  cluster_config {
    instance_type = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  log_publishing_options {
    log_type = "AUDIT_LOGS"
    enabled  = true
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.pass_log_group.arn
  }

  tags = {
    Environment = "production"
  }
}