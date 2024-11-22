provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create ECR repository without tag immutability
resource "aws_ecr_repository" "fail_repo" {
  provider = aws.fail_aws
  name = "fail-repo"
  image_tag_mutability = "MUTABLE"

  tags = {
    Environment = "Development"
  }
}