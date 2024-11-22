provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_db_instance" "pass_test" {
  provider                = aws.pass_aws
  identifier              = "pass-test-db"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "password123!"
  skip_final_snapshot     = true
  
  # Enable IAM authentication
  iam_database_authentication_enabled = true

  # Enable encryption
  storage_encrypted = true

  # Enable automated backups
  backup_retention_period = 7

  # Enable enhanced monitoring
  monitoring_interval = 60

  tags = {
    Environment = "production"
    Security    = "high"
  }
}
