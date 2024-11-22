provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_codebuild_project" "pass_project" {
  provider = aws.pass_aws
  name = "pass-test-project"
  description = "test project with secure environment variables"
  service_role = "arn:aws:iam::123456789012:role/example"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image = "aws/codebuild/standard:4.0"
    type = "LINUX_CONTAINER"

    environment_variable {
      name = "AWS_ACCESS_KEY_ID"
      value = "/codebuild/dev/aws-access-key-id"
      type = "PARAMETER_STORE"
    }

    environment_variable {
      name = "AWS_SECRET_ACCESS_KEY"
      value = "arn:aws:secretsmanager:us-west-2:123456789012:secret:dev/aws-secret-access-key"
      type = "SECRETS_MANAGER"
    }
  }

  source {
    type = "NO_SOURCE"
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo \"Nothing to do!\""
  }
}