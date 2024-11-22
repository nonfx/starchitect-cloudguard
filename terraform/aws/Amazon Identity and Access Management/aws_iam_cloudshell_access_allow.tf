# Define provider
provider "aws" {
  region = "us-east-1"
}

# Create IAM user
resource "aws_iam_user" "example_user" {
  name = "example_user"
}

# Create IAM role
resource "aws_iam_role" "example_role" {
  name = "example_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com",
        },
      },
    ],
  })
}

# Create IAM group
resource "aws_iam_group" "example_group" {
  name = "example_group"
}

# Create IAM policy attachment for the user (other policy, not AWSCloudShellFullAccess)
resource "aws_iam_user_policy_attachment" "example_user_policy_attachment" {
  user       = aws_iam_user.example_user.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"  # Different policy
}

# Create IAM policy attachment for the role (other policy, not AWSCloudShellFullAccess)
resource "aws_iam_role_policy_attachment" "example_role_policy_attachment" {
  role       = aws_iam_role.example_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"  # Different policy
}

# Create IAM policy attachment for the group (other policy, not AWSCloudShellFullAccess)
resource "aws_iam_group_policy_attachment" "example_group_policy_attachment" {
  group      = aws_iam_group.example_group.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess"  # Different policy
}
