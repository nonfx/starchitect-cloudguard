provider "aws" {
  region = "us-west-2"
}

# RDS instance without CloudWatch logs configured
resource "aws_db_instance" "fail_example" {
  identifier             = "postgresql-instance-fail"
  engine                 = "postgres"
  engine_version         = "13.7"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "adminuser"
  password               = "testpassword123"
  skip_final_snapshot    = true
  
  # Missing enabled_cloudwatch_logs_exports configuration
  
  tags = {
    Environment = "test"
  }
}
