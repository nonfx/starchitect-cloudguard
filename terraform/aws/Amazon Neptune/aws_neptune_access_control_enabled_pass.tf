provider "aws" {
  region = "us-west-2"
}

resource "aws_neptune_cluster" "example" {
  cluster_identifier  = "neptune-cluster-demo"
  engine              = "neptune"
  skip_final_snapshot = true
  apply_immediately   = true
  iam_database_authentication_enabled = true
  iam_roles           = [aws_iam_role.neptune_access.arn]
}

resource "aws_iam_role" "neptune_access" {
  name = "neptune-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "neptune_access" {
  name = "neptune-access-policy"
  role = aws_iam_role.neptune_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "neptune-db:Read",
          "neptune-db:Write"
        ]
        Effect   = "Allow"
        Resource = aws_neptune_cluster.example.arn
      }
    ]
  })
}

resource "aws_iam_user" "neptune_user" {
  name = "neptune-user"
}

resource "aws_iam_user_policy" "neptune_user_policy" {
  name = "neptune-user-policy"
  user = aws_iam_user.neptune_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "neptune-db:Read"
        ]
        Effect   = "Allow"
        Resource = aws_neptune_cluster.example.arn
      }
    ]
  })
}

resource "aws_iam_group" "neptune_group" {
  name = "neptune-group"
}

resource "aws_iam_group_policy" "neptune_group_policy" {
  name  = "neptune-group-policy"
  group = aws_iam_group.neptune_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "neptune-db:Read",
          "neptune-db:Write"
        ]
        Effect   = "Allow"
        Resource = aws_neptune_cluster.example.arn
      }
    ]
  })
}

resource "aws_iam_policy" "neptune_policy" {
  name        = "neptune-policy"
  description = "Neptune access policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "neptune-db:Read",
          "neptune-db:Write"
        ]
        Effect   = "Allow"
        Resource = aws_neptune_cluster.example.arn
      }
    ]
  })
}
