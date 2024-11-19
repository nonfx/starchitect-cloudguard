provider "aws" {
  region = "us-west-2"
}

resource "aws_db_instance" "default" {
  instance_class         = "db.t3.micro"
  publicly_accessible = false
  auto_minor_version_upgrade = true
  storage_encrypted = true
}
