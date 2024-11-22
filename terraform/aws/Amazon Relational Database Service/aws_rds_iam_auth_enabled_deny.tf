provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_db_instance" "fail_test" {
  provider                = aws.fail_aws
  identifier              = "fail-test-db"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "password123!"
  skip_final_snapshot     = true
  
  # IAM authentication disabled
  iam_database_authentication_enabled = false

  tags = {
    Environment = "test"
  }
}
