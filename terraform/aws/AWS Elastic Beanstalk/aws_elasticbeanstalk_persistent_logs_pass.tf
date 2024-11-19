provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_elastic_beanstalk_application" "passing_app" {
  provider    = aws.passing
  name        = "passing-app"
  description = "passing-app-description"
}

resource "aws_elastic_beanstalk_environment" "passing_env" {
  provider            = aws.passing
  name                = "passing-env"
  application         = aws_elastic_beanstalk_application.passing_app.name
  solution_stack_name = "64bit Amazon Linux 2 v3.4.1 running Python 3.8"

  setting {
    namespace = "aws:elasticbeanstalk:cloudwatch:logs"
    name      = "StreamLogs"
    value     = "true"
  }

  setting {
    namespace = "aws:elasticbeanstalk:cloudwatch:logs"
    name      = "DeleteOnTerminate"
    value     = "false"
  }

  setting {
    namespace = "aws:elasticbeanstalk:cloudwatch:logs"
    name      = "RetentionInDays"
    value     = "30"
  }
}
