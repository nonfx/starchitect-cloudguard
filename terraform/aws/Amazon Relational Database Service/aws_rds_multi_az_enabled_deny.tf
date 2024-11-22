provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create RDS instance without Multi-AZ
resource "aws_db_instance" "fail_test" {
  provider             = aws.fail_aws
  identifier           = "fail-test-db"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  skip_final_snapshot  = true
  multi_az             = false

  tags = {
    Environment = "test"
  }
}