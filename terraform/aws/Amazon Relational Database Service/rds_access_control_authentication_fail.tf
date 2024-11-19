resource "aws_db_instance" "fail_example" {
  identifier           = "mydb-fail"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true

  publicly_accessible                   = true
  iam_database_authentication_enabled   = false
}
