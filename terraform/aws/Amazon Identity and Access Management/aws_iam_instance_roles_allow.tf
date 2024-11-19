provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "passing_role" {
  name = "passing_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {"Service": "ec2.amazonaws.com"}
    }]
  })
}

resource "aws_iam_instance_profile" "passing_profile" {
  name = "passing_profile"
  role = aws_iam_role.passing_role.name
}

resource "aws_instance" "passing_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.passing_profile.id
  tags = {
    Name = "Passing Instance"
  }
}
