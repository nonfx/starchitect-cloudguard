provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_db_instance" "pass_test" {
  provider = aws.pass_aws
  identifier = "pass-test-db"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  
  # Enable deletion protection
  deletion_protection = true
  
  tags = {
    Environment = "production"
  }
}