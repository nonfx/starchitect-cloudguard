provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

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
  
  # Failing configuration: backup retention period less than 7 days
  backup_retention_period = 3

  tags = {
    Environment = "test"
  }
}
