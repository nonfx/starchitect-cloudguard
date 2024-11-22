# Configure AWS provider for us-east-1 region (required for WAF Classic Global)
provider "aws" {
  region = "us-east-1"
}

# Create S3 bucket for WAF logs
resource "aws_s3_bucket" "pass_waf_log_bucket" {
  bucket = "pass-waf-logs-bucket"
}

# Create WAF Web ACL
resource "aws_waf_web_acl" "pass_waf_acl" {
  name        = "pass-waf-acl"
  metric_name = "passWafAcl"

  # Define default action for the Web ACL
  default_action {
    type = "ALLOW"
  }

  # Add a sample rule
  rules {
    action {
      type = "BLOCK"
    }
    priority = 1
    rule_id  = aws_waf_rule.pass_waf_rule.id
    type     = "REGULAR"
  }
}

# Create a basic WAF rule
resource "aws_waf_rule" "pass_waf_rule" {
  name        = "pass-waf-rule"
  metric_name = "passWafRule"
}

# Enable logging configuration for the WAF Web ACL
resource "aws_waf_web_acl_logging_configuration" "pass_waf_logging" {
  log_destination = aws_s3_bucket.pass_waf_log_bucket.arn
  resource_arn    = aws_waf_web_acl.pass_waf_acl.id
}