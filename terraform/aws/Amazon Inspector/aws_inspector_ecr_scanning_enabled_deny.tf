provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# ECR repository with scanning disabled - this will fail the policy check
resource "aws_ecr_repository" "fail_repo" {
  provider = aws.fail_aws
  name = "fail-repo"

  image_scanning_configuration {
    scan_on_push = false
  }
}
