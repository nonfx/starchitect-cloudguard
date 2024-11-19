provider "aws" {
  region = "us-west-2"
  alias  = "failing"
}

# VPC is defined but not used
resource "aws_vpc" "main" {
  provider   = aws.failing
  cidr_block = "10.0.0.0/16"
}

resource "aws_db_instance" "failing_instance" {
  provider             = aws.failing
  identifier           = "failing-rds-instance"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true

  # Not specifying a db_subnet_group_name
}
