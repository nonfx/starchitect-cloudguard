provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_dms_endpoint" "pass_test" {
  provider      = aws.pass_aws
  endpoint_id   = "redis-endpoint-pass"
  endpoint_type = "target"
  engine_name   = "redis"

  # SSL mode set to verify-full, which passes the policy
  ssl_mode = "verify-full"

  redis_settings {
    server_name           = "redis.example.com"
    port                  = 6379
    auth_type             = "auth-token"
    ssl_security_protocol = "TLS1_2"
  }
}
