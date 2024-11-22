# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create RDS instance with non-default port (passing case)
resource "aws_db_instance" "pass_test" {
  identifier             = "pass-test-db"
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "password123!"
  port                   = 3307  # Using non-default port (will pass test)
  skip_final_snapshot    = true

  tags = {
    Environment = "production"
    Name        = "pass-test-db"
  }
}
