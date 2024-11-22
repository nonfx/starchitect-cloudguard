provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create RDS instance with public access enabled - This configuration fails security best practices
resource "aws_db_instance" "fail_test" {
  provider = aws.fail_aws
  identifier = "fail-test-db"
  engine = "mysql"
  engine_version = "5.7"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true
  publicly_accessible = true  # This setting makes the database publicly accessible, which is a security risk

  tags = {
    Environment = "test"
    Name = "fail-test-db"
  }
}