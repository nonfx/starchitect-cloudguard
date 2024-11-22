provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create ECR repository without image scanning
resource "aws_ecr_repository" "fail_repository" {
  provider = aws.fail_aws
  name = "fail-repository"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = {
    Environment = "Development"
    Purpose = "Testing"
  }
}
