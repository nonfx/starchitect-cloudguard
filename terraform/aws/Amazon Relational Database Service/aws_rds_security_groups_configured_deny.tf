provider "aws" {
  region = "us-west-2"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "incomplete_sg" {
  name        = "incomplete-sg"
  description = "Incomplete security group"
  vpc_id      = aws_vpc.main.id

  # No ingress or egress rules defined
}

resource "aws_db_instance" "failing_example" {
  identifier           = "failing-example"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true

  vpc_security_group_ids = [aws_security_group.incomplete_sg.id]
}
