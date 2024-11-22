provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_db_instance" "passing_example" {
  provider             = aws.passing
  identifier           = "passing-example-db"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true

  backup_retention_period = 7  # This enables automated backups with a 7-day retention period
}
