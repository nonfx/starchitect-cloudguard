provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "support_role" {
  name = "SupportRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "support.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "support_role_policy_attachment" {
  role       = aws_iam_role.support_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}
