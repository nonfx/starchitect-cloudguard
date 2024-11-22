provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create ECR repository with tag immutability enabled
resource "aws_ecr_repository" "pass_repo" {
  provider = aws.pass_aws
  name = "pass-repo"
  image_tag_mutability = "IMMUTABLE"

  # Enable image scanning
  image_scanning_configuration {
    scan_on_push = true
  }

  # Enable encryption
  encryption_configuration {
    encryption_type = "KMS"
  }

  tags = {
    Environment = "Production"
    SecurityCompliance = "True"
  }
}