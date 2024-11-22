provider "aws" {
  region = "us-west-2"
}

resource "aws_neptune_cluster" "example" {
  cluster_identifier  = "neptune-cluster-demo"
  engine              = "neptune"
  skip_final_snapshot = true
  apply_immediately   = true

  # No IAM roles associated
}

resource "aws_iam_role" "example" {
  name = "neptune-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  # No Neptune access policy attached
}
