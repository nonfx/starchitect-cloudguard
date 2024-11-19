provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_dms_endpoint" "fail_test" {
  provider = aws.fail_aws
  endpoint_id = "fail-dms-endpoint"
  endpoint_type = "source"
  engine_name = "mysql"
  
  server_name = "database-1"
  port = 3306
  database_name = "test"
  username = "admin"
  password = "password123"
  
  ssl_mode = "none"
}
