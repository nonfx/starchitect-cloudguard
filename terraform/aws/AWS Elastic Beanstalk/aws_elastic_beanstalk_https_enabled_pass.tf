resource "aws_elastic_beanstalk_application" "example_app" {
  name        = "example-app"
  description = "Example Elastic Beanstalk Application"
}

resource "aws_elastic_beanstalk_environment" "example_env" {
  name                = "example-env"
  application         = aws_elastic_beanstalk_application.example_app.name
  solution_stack_name = "64bit Amazon Linux 2 v3.4.9 running Python 3.8"

  setting {
    namespace = "aws:elb:listener:443"
    name      = "ListenerProtocol"
    value     = "HTTPS"
  }

  setting {
    namespace = "aws:elb:listener:443"
    name      = "SSLCertificateId"
    value     = "arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012"
  }

  setting {
    namespace = "aws:elb:listener:443"
    name      = "InstancePort"
    value     = 80
  }

  setting {
    namespace = "aws:elb:listener:443"
    name      = "InstanceProtocol"
    value     = "HTTP"
  }
}
