provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "authorized_role" {
  name = "AuthorizedRoleName1"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_user" "authorized_user" {
  name = "AuthorizedUserName1"
}

resource "aws_iam_group" "authorized_group" {
  name = "AuthorizedGroupName1"
}

resource "aws_iam_role_policy_attachment" "authorized_role_policy_attachment" {
  role       = aws_iam_role.authorized_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
}

resource "aws_iam_user_policy_attachment" "authorized_user_policy_attachment" {
  user       = aws_iam_user.authorized_user.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
}

resource "aws_iam_group_policy_attachment" "authorized_group_policy_attachment" {
  group      = aws_iam_group.authorized_group.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
}
