provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_elasticsearch_domain" "fail_domain" {
  provider = aws.fail_aws
  domain_name           = "fail-es-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # Audit logging is disabled
  log_publishing_options {
    log_type = "AUDIT_LOGS"
    enabled  = false
    cloudwatch_log_group_arn = null
  }

  tags = {
    Environment = "test"
  }
}