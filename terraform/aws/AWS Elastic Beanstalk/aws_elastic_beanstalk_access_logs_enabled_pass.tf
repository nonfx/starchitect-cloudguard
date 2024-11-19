resource "aws_elastic_beanstalk_application" "app" {
  name        = "example-app"
  description = "An example application"
}

resource "aws_elastic_beanstalk_environment" "env" {
  name                = "example-env"
  application         = aws_elastic_beanstalk_application.app.name
  solution_stack_name = "64bit Amazon Linux 2 v3.3.10 running Python 3.8"

  setting {
    namespace = "aws:elbv2:loadbalancer"
    name      = "AccessLogsS3Enabled"
    value     = "true"
  }

  setting {
    namespace = "aws:elbv2:loadbalancer"
    name      = "AccessLogsS3Bucket"
    value     = "my-logs-bucket"
  }

  setting {
    namespace = "aws:elbv2:loadbalancer"
    name      = "AccessLogsS3Prefix"
    value     = "elasticbeanstalk-logs"
  }

  # //For elb
  #   setting {
  #   namespace = "aws:elb:loadbalancer"
  #   name      = "AccessLogsS3Enabled"
  #   value     = "true"
  # }

  # setting {
  #   namespace = "aws:elb:loadbalancer"
  #   name      = "AccessLogsS3Bucket"
  #   value     = "my-logs-bucket"
  # }

  # setting {
  #   namespace = "aws:elb:loadbalancer"
  #   name      = "AccessLogsS3Prefix"
  #   value     = "elasticbeanstalk-logs"
  # }
}
