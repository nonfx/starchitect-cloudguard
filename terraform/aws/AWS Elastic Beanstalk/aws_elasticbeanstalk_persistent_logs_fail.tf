provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_elastic_beanstalk_application" "failing_app" {
  provider    = aws.failing
  name        = "failing-app"
  description = "failing-app-description"
}

resource "aws_elastic_beanstalk_environment" "failing_env" {
  provider            = aws.failing
  name                = "failing-env"
  application         = aws_elastic_beanstalk_application.failing_app.name
  solution_stack_name = "64bit Amazon Linux 2 v3.4.1 running Python 3.8"

  setting {
    namespace = "aws:elasticbeanstalk:cloudwatch:logs"
    name      = "StreamLogs"
    value     = "false"
  }
}
