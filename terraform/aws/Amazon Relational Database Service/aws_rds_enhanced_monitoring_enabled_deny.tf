provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_db_instance" "fail_test" {
  provider = aws.fail_aws
  identifier = "fail-test-db"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  
  # Invalid monitoring configuration - monitoring interval is 0 and no role ARN
  monitoring_interval = 0
  monitoring_role_arn = ""
  
  tags = {
    Environment = "test"
    Purpose = "testing"
  }
}
