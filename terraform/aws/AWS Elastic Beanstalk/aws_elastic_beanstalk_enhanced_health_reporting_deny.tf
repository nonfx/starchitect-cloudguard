provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_elastic_beanstalk_application" "fail_app" {
  provider = aws.fail_aws
  name        = "fail-app"
  description = "fail-app-description"
}

resource "aws_elastic_beanstalk_environment" "fail_env" {
  provider = aws.fail_aws
  name                = "fail-env"
  application         = aws_elastic_beanstalk_application.fail_app.name
  solution_stack_name = "64bit Amazon Linux 2 v3.4.1 running Python 3.8"

  setting {
    namespace = "aws:elasticbeanstalk:healthreporting:system"
    name      = "SystemType"
    value     = "basic"
  }
}