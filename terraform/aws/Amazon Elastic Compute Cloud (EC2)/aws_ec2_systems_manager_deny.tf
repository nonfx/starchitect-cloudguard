provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_instance" "failing_example" {
  provider = aws.failing
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  tags = {
    Name = "failing-example"
  }
}

resource "aws_iam_role" "failing_role" {
  provider = aws.failing
  name = "failing_ssm_role"
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
}

resource "aws_iam_instance_profile" "failing_profile" {
  provider = aws.failing
  name = "failing_ssm_profile"
  role = aws_iam_role.failing_role.name
}

# This instance has a profile, but the role doesn't have the correct policy
resource "aws_instance" "failing_example_2" {
  provider = aws.failing
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.failing_profile.name

  tags = {
    Name = "failing-example-2"
  }
}
