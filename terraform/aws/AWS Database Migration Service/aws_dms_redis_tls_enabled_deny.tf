provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_dms_endpoint" "fail_test" {
  provider      = aws.fail_aws
  endpoint_id   = "redis-endpoint-fail"
  endpoint_type = "target"
  engine_name   = "redis"

  # SSL mode set to none, which fails the policy
  ssl_mode = "none"

  redis_settings {
    server_name = "redis.example.com"
    port        = 6379
    auth_type   = "auth-token"
  }
}
