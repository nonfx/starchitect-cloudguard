provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# ECR repository with scanning enabled - this will pass the policy check
resource "aws_ecr_repository" "pass_repo" {
  provider = aws.pass_aws
  name = "pass-repo"

  # Enable scanning on push for security compliance
  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Environment = "Production"
    Purpose = "Container Registry"
  }
}
