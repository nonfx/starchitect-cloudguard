provider "aws" {
  region = "us-west-2"
}

resource "aws_elastic_beanstalk_environment" "failing_environment" {
  name                = "failing-environment"
  application         = "my-app"
  solution_stack_name = "64bit Amazon Linux 2 v3.4.1 running Python 3.8"

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = "aws-elasticbeanstalk-ec2-role"
  }

  # Managed updates are not enabled
  setting {
    namespace = "aws:elasticbeanstalk:managedactions"
    name      = "ManagedActionsEnabled"
    value     = "false"
  }
}
