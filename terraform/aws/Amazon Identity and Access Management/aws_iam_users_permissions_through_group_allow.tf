provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_user" "user" {
  name = "test_user"
}

resource "aws_iam_group" "group" {
  name = "test_group"
}

resource "aws_iam_group_membership" "group_membership" {
  name  = "group_membership"
  group = aws_iam_group.group.name
  users = [aws_iam_user.user.name]
}
