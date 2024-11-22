provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "incorrect_role" {
  name = "incorrect_keyspaces_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Effect = "Allow",
      Sid = ""
    }]
  })
}

resource "aws_iam_role_policy" "incorrect_policy" {
  name   = "incorrect_keyspaces_policy"
  role = aws_iam_role.incorrect_role.name
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = [
        "ec2:Describe*"
      ],
      Effect = "Allow",
      Resource = "*"
    }]
  })
}

resource "aws_keyspaces_keyspace" "example" {
  name = "example"
}

resource "aws_keyspaces_table" "example" {
  table_name = "example"
  keyspace_name = aws_keyspaces_keyspace.example.name
  schema_definition {
    column {
      name = "id"
      type = "uuid"
    }
    column {
      name = "name"
      type = "text"
    }
    partition_key {
      name = "id"
    }
    clustering_key {
      name = "name"
      order_by = "ASC"
    }
  }
}