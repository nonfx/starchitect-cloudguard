provider "aws" {
  alias  = "passing"
  region = "us-east-1"
}

resource "aws_vpc" "passing_example" {
  provider = aws.passing
  cidr_block = "10.0.0.0/16"
}

resource "aws_vpc_endpoint" "passing_example" {
  provider = aws.passing
  vpc_id       = aws_vpc.passing_example.id
  service_name = "com.amazonaws.vpce.us-east-1.apprunner.requests"
  vpc_endpoint_type = "Interface"
}

resource "aws_apprunner_vpc_connector" "passing_example" {
  provider = aws.passing
  vpc_connector_name = "example"
  subnets            = ["subnet-12345678", "subnet-87654321"]
  security_groups    = ["sg-12345678"]
}

resource "aws_apprunner_service" "passing_example" {
  provider = aws.passing
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

  network_configuration {
    egress_configuration {
      egress_type       = "VPC"
      vpc_connector_arn = aws_apprunner_vpc_connector.passing_example.arn
    }
  }

  tags = {
    Name = "example-apprunner-service"
  }
}
