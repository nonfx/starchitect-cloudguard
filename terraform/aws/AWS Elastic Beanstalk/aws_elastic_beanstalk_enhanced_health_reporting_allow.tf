provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_elastic_beanstalk_application" "pass_app" {
  provider = aws.pass_aws
  name        = "pass-app"
  description = "pass-app-description"
}

resource "aws_elastic_beanstalk_environment" "pass_env" {
  provider = aws.pass_aws
  name                = "pass-env"
  application         = aws_elastic_beanstalk_application.pass_app.name
  solution_stack_name = "64bit Amazon Linux 2 v3.4.1 running Python 3.8"

  setting {
    namespace = "aws:elasticbeanstalk:healthreporting:system"
    name      = "SystemType"
    value     = "enhanced"
  }

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = "aws-elasticbeanstalk-ec2-role"
  }
}