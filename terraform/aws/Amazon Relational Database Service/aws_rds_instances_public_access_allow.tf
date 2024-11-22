provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create RDS instance with secure configuration following best practices
resource "aws_db_instance" "pass_test" {
  provider = aws.pass_aws
  identifier = "pass-test-db"
  engine = "mysql"
  engine_version = "5.7"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true
  publicly_accessible = false  # Properly configured to prevent public access

  # Enable encryption at rest for additional security
  storage_encrypted = true

  # Configure backup retention for disaster recovery
  backup_retention_period = 7
  backup_window = "03:00-04:00"

  # Enable enhanced monitoring for better operational visibility
  monitoring_interval = 60

  tags = {
    Environment = "production"
    Name = "pass-test-db"
  }
}