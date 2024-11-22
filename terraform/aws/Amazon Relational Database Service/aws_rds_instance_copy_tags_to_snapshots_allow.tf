# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create RDS instance with copy_tags_to_snapshot enabled
resource "aws_db_instance" "pass_example" {
  identifier             = "pass-db-instance"
  engine                 = "mysql"
  engine_version         = "8.0.28"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "password123!"
  skip_final_snapshot    = true
  copy_tags_to_snapshot  = true  # Explicitly enabled

  tags = {
    Environment = "production"
    Project     = "test"
    Backup      = "enabled"
  }
}
