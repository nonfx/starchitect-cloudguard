provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_codebuild_project" "pass_project" {
  provider = aws.pass_aws
  name = "pass-test-project"
  description = "test project"
  service_role = "arn:aws:iam::123456789012:role/example"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image = "aws/codebuild/standard:4.0"
    type = "LINUX_CONTAINER"
  }

  source {
    type = "BITBUCKET"
    location = "https://bitbucket.org/org/repo.git"
  }

  secondary_sources {
    type = "BITBUCKET" 
    source_identifier = "secondary"
    location = "https://bitbucket.org/org/repo2.git"
  }
}