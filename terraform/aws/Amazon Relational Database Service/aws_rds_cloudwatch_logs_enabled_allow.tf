provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_db_instance" "pass_test" {
  provider = aws.pass_aws
  identifier = "pass-test-db"
  engine = "mysql"
  engine_version = "8.0.28"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true
  
  # Enable all required log exports for MySQL
  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
  
  tags = {
    Environment = "production"
  }
}