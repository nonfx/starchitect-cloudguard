provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_db_instance" "failing_example" {
  provider             = aws.failing
  identifier           = "failing-example-db"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true

  backup_retention_period = 0  # This disables automated backups
}
