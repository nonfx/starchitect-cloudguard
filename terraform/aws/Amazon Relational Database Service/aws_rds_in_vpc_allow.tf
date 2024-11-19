provider "aws" {
  region = "us-west-2"
  alias  = "passing"
}

resource "aws_vpc" "main" {
  provider   = aws.passing
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "main" {
  provider   = aws.passing
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_db_subnet_group" "main" {
  provider   = aws.passing
  name       = "main"
  subnet_ids = [aws_subnet.main.id]
}

resource "aws_db_instance" "passing_instance" {
  provider             = aws.passing
  identifier           = "passing-rds-instance"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true
  db_subnet_group_name = aws_db_subnet_group.main.name
}
