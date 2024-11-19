provider "aws" {
  region = "us-west-2"
}

# Create ECR repository with proper configuration
resource "aws_ecr_repository" "pass_repository" {
  name = "pass-repository"
  
  # Enable image scanning on push for security
  image_scanning_configuration {
    scan_on_push = true
  }

  # Add tags for better resource management
  tags = {
    Environment = "Production"
    Purpose = "Application"
  }
}

# Configure lifecycle policy to manage image retention
resource "aws_ecr_lifecycle_policy" "pass_policy" {
  repository = aws_ecr_repository.pass_repository.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Retain only last 30 images"
        selection = {
          tagStatus     = "any"
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}