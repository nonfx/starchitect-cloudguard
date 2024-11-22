provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create CloudWatch log group
resource "aws_cloudwatch_log_group" "pass_es_log_group" {
  provider = aws.pass_aws
  name = "pass-es-log-group"
  retention_in_days = 30
}

# Create Elasticsearch domain with error logging enabled
resource "aws_elasticsearch_domain" "pass_example" {
  provider = aws.pass_aws
  domain_name = "pass-es-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
    instance_count = 2
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # Enable error logging to CloudWatch Logs
  log_publishing_options {
    log_type = "ES_APPLICATION_LOGS"
    enabled = true
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.pass_es_log_group.arn
  }

  tags = {
    Environment = "production"
  }
}