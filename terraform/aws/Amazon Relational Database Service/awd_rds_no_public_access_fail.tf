provider "aws" {
  region = "us-west-2"
}

resource "aws_db_instance" "default" {
  instance_class         = "db.t3.micro"
  publicly_accessible = true
}

resource "aws_db_instance" "userdb" {
  instance_class         = "db.t3.micro"
  # publicly_accessible = true
}
