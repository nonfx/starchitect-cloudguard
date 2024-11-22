provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create RDS instance with Multi-AZ enabled
resource "aws_db_instance" "pass_test" {
  provider             = aws.pass_aws
  identifier           = "pass-test-db"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  skip_final_snapshot  = true
  multi_az             = true
  backup_retention_period = 7
  backup_window        = "03:00-04:00"
  maintenance_window   = "Mon:04:00-Mon:05:00"

  tags = {
    Environment = "production"
  }
}