provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create VPC resources
resource "aws_vpc" "pass_test" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "pass-test-vpc"
  }
}

resource "aws_subnet" "pass_test_1" {
  provider = aws.pass_aws
  vpc_id     = aws_vpc.pass_test.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "pass-test-subnet-1"
  }
}

resource "aws_subnet" "pass_test_2" {
  provider = aws.pass_aws
  vpc_id     = aws_vpc.pass_test.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "pass-test-subnet-2"
  }
}

resource "aws_db_subnet_group" "pass_test" {
  provider = aws.pass_aws
  name       = "pass-test-subnet-group"
  subnet_ids = [aws_subnet.pass_test_1.id, aws_subnet.pass_test_2.id]

  tags = {
    Name = "pass-test-db-subnet-group"
  }
}

# Create security group for RDS
resource "aws_security_group" "pass_test_rds" {
  provider = aws.pass_aws
  name        = "pass-test-rds-sg"
  description = "Security group for RDS instance"
  vpc_id      = aws_vpc.pass_test.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

# Create RDS instance in VPC with both subnet group and security group
resource "aws_db_instance" "pass_test" {
  provider               = aws.pass_aws
  identifier             = "pass-test-db"
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "password123"
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.pass_test.name
  vpc_security_group_ids = [aws_security_group.pass_test_rds.id]
  publicly_accessible    = false

  tags = {
    Environment = "production"
    Purpose     = "testing"
  }
}
