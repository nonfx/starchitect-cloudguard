provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create ECR repository with image scanning enabled
resource "aws_ecr_repository" "pass_repository" {
  provider = aws.pass_aws
  name = "pass-repository"

  image_scanning_configuration {
    scan_on_push = true
  }

  # Enable image tag immutability for additional security
  image_tag_mutability = "IMMUTABLE"

  tags = {
    Environment = "Production"
    Security = "High"
  }
}
