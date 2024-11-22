provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_dms_endpoint" "pass_test" {
  provider = aws.pass_aws
  endpoint_id = "pass-dms-endpoint"
  endpoint_type = "source"
  engine_name = "mysql"
  
  server_name = "database-1"
  port = 3306
  database_name = "test"
  username = "admin"
  password = "password123"
  
  ssl_mode = "verify-full"
  
  certificate_arn = "arn:aws:dms:us-west-2:123456789012:cert:test-cert"
}
