provider "aws" {
  region = "us-west-2"
}

# RDS instance with CloudWatch logs properly configured
resource "aws_db_instance" "pass_example" {
  identifier             = "postgresql-instance-pass"
  engine                 = "postgres"
  engine_version         = "13.7"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "adminuser"
  password               = "testpassword123"
  skip_final_snapshot    = true
  
  # Configure PostgreSQL logs export to CloudWatch
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  tags = {
    Environment = "production"
  }
}
