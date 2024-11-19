provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create CloudWatch log group for DNS queries
resource "aws_cloudwatch_log_group" "pass_dns_log_group" {
  provider = aws.pass_aws
  name = "/aws/route53/example-pass.com"
  retention_in_days = 30

  tags = {
    Environment = "production"
  }
}

# Create Route53 zone
resource "aws_route53_zone" "pass_zone" {
  provider = aws.pass_aws
  name = "example-pass.com"

  tags = {
    Environment = "production"
  }
}

# Enable query logging for the zone
resource "aws_route53_query_log" "pass_query_log" {
  provider = aws.pass_aws
  depends_on = [aws_cloudwatch_log_group.pass_dns_log_group]

  cloudwatch_log_group_arn = aws_cloudwatch_log_group.pass_dns_log_group.arn
  zone_id = aws_route53_zone.pass_zone.zone_id
}