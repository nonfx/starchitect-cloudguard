provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_codebuild_project" "fail_project" {
  provider = aws.fail_aws
  name = "fail-test-project"
  description = "test project with credentials in environment variables"
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
      value = "AKIAIOSFODNN7EXAMPLE"
      type = "PLAINTEXT"
    }

    environment_variable {
      name = "AWS_SECRET_ACCESS_KEY"
      value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      type = "PLAINTEXT"
    }
  }

  source {
    type = "NO_SOURCE"
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo \"Nothing to do!\""
  }
}