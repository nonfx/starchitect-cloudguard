resource "aws_db_instance" "fail_example" {
  identifier           = "example-db"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  storage_type         = "gp2"
  username             = "admin"
  password             = "password123"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true
  storage_encrypted    = false  # Failing because encryption at rest is not enabled
}
