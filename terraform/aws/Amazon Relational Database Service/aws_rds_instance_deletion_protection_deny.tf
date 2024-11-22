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
  
  # Deletion protection disabled
  deletion_protection = false
  
  tags = {
    Environment = "test"
  }
}