provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_cloudwatch_log_group" "pass_example" {
  provider          = aws.pass_aws
  name              = "/aws/opensearch/domains/pass-example-domain"
  retention_in_days = 30
}

resource "aws_opensearch_domain" "pass_example" {
  provider    = aws.pass_aws
  domain_name = "pass-example-domain"

  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  log_publishing_options {
    enabled                  = true
    log_type                 = "INDEX_SLOW_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.pass_example.arn
  }

  tags = {
    Environment = "production"
  }
}
