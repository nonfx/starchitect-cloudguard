# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create RDS instance with default port (failing case)
resource "aws_db_instance" "fail_test" {
  identifier             = "fail-test-db"
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "password123!"
  port                   = 3306  # Using default MySQL port (will fail test)
  skip_final_snapshot    = true

  tags = {
    Environment = "test"
    Name        = "fail-test-db"
  }
}
