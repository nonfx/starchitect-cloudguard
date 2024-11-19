provider "aws" {
  alias  = "failing"
  region = "us-east-1"
}

resource "aws_apprunner_service" "failing_example" {
  provider = aws.failing
  service_name = "example"

  source_configuration {
    auto_deployments_enabled = false
    image_repository {
      image_configuration {
        port = "8080"
      }
      image_identifier      = "public.ecr.aws/aws-containers/hello-app-runner:latest"
      image_repository_type = "ECR_PUBLIC"
    }
  }

  tags = {
    Name = "example-apprunner-service"
  }
}
