provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create CloudWatch log group for audit logs
resource "aws_cloudwatch_log_group" "es_audit_logs" {
  provider = aws.pass_aws
  name              = "/aws/elasticsearch/domains/pass-es-domain/audit-logs"
  retention_in_days = 30
}

resource "aws_elasticsearch_domain" "pass_domain" {
  provider = aws.pass_aws
  domain_name           = "pass-es-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # Enable audit logging with CloudWatch configuration
  log_publishing_options {
    log_type                 = "AUDIT_LOGS"
    enabled                  = true
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es_audit_logs.arn
  }

  tags = {
    Environment = "production"
  }

  depends_on = [aws_cloudwatch_log_group.es_audit_logs]
}