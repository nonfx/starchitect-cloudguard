provider "aws" {
  region = "us-west-2"
}

# Create ECR repository without lifecycle policy
resource "aws_ecr_repository" "fail_repository" {
  name = "fail-repository"
  
  # Enable image scanning on push
  image_scanning_configuration {
    scan_on_push = true
  }

  # Add tags for better resource management
  tags = {
    Environment = "Development"
    Purpose = "Testing"
  }
}