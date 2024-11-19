resource "aws_db_instance" "test" {
  identifier        = "test-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "customadmin"
  password          = "password123!"
  skip_final_snapshot = true
}