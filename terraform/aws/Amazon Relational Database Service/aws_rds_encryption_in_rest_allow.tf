resource "aws_db_instance" "pass_example" {
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
  storage_encrypted    = true  # Passing because encryption at rest is enabled
  kms_key_id           = aws_kms_key.example.arn  # Using a customer-managed KMS key
}

resource "aws_kms_key" "example" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 10
}
